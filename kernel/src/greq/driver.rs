// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Driver to send `SNP_GUEST_REQUEST` commands to the PSP. It can be any of the
//! request or response command types defined in the SEV-SNP spec, regardless if it's
//! a regular or an extended command.

extern crate alloc;

use alloc::boxed::Box;
use core::{cell::OnceCell, mem::size_of};
use zerocopy::FromZeros;

use crate::mm::alloc::AllocError;
use crate::mm::page_visibility::SharedBox;
use crate::{
    cpu::percpu::current_ghcb,
    error::SvsmError,
    greq::msg::{SnpGuestRequestExtData, SnpGuestRequestMsg, SnpGuestRequestMsgType},
    locking::SpinLock,
    protocols::errors::{SvsmReqError, SvsmResultCode},
    sev::{ghcb::GhcbError, secrets_page, secrets_page_mut, VMPCK_SIZE},
    types::PAGE_SHIFT,
    BIT,
};

/// Global `SNP_GUEST_REQUEST` driver instance
static GREQ_DRIVER: SpinLock<OnceCell<SnpGuestRequestDriver>> = SpinLock::new(OnceCell::new());

// Hypervisor error codes

/// Buffer provided is too small
const SNP_GUEST_REQ_INVALID_LEN: u64 = BIT!(32);
/// Hypervisor busy, try again
const SNP_GUEST_REQ_ERR_BUSY: u64 = BIT!(33);

/// Class of the `SNP_GUEST_REQUEST` command: Regular or Extended
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum SnpGuestRequestClass {
    Regular = 0,
    Extended = 1,
}

/// `SNP_GUEST_REQUEST` driver
#[derive(Debug)]
struct SnpGuestRequestDriver {
    /// Shared page used for the `SNP_GUEST_REQUEST` request
    request: SharedBox<SnpGuestRequestMsg>,
    /// Shared page used for the `SNP_GUEST_REQUEST` response
    response: SharedBox<SnpGuestRequestMsg>,
    /// Encrypted page where we perform crypto operations
    staging: Box<SnpGuestRequestMsg>,
    /// Extended data buffer that will be provided to the hypervisor
    /// to store the SEV-SNP certificates
    ext_data: SharedBox<SnpGuestRequestExtData>,
    /// Extended data size (`certs` size) provided by the user in [`super::services::get_extended_report`].
    /// It will be provided to the hypervisor.
    user_extdata_size: usize,
    /// Each `SNP_GUEST_REQUEST` message contains a sequence number per VMPCK.
    /// The sequence number is incremented with each message sent. Messages
    /// sent by the guest to the PSP and by the PSP to the guest must be
    /// delivered in order. If not, the PSP will reject subsequent messages
    /// by the guest when it detects that the sequence numbers are out of sync.
    ///
    /// NOTE: If the vmpl field of a `SNP_GUEST_REQUEST` message is set to VMPL0,
    /// then it must contain the VMPL0 sequence number and be protected (encrypted)
    /// with the VMPCK0 key; additionally, if this message fails, the VMPCK0 key
    /// must be disabled. The same idea applies to the other VMPL levels.
    ///
    /// The SVSM needs to support only VMPL0 `SNP_GUEST_REQUEST` commands because
    /// other layers in the software stack (e.g. OVMF and guest kernel) can send
    /// non-VMPL0 commands directly to PSP. Therefore, the SVSM needs to maintain
    /// the sequence number and the VMPCK only for VMPL0.
    vmpck0_seqno: u64,
}

impl SnpGuestRequestDriver {
    /// Create a new [`SnpGuestRequestDriver`]
    pub fn new() -> Result<Self, SvsmReqError> {
        let request = SharedBox::try_new_zeroed()?;
        let response = SharedBox::try_new_zeroed()?;
        let staging = SnpGuestRequestMsg::new_box_zeroed()
            .map_err(|_| SvsmError::Alloc(AllocError::OutOfMemory))?;
        let ext_data = SharedBox::try_new_zeroed()?;

        Ok(Self {
            request,
            response,
            staging,
            ext_data,
            user_extdata_size: size_of::<SnpGuestRequestExtData>(),
            vmpck0_seqno: 0,
        })
    }

    /// Get the last VMPCK0 sequence number accounted
    fn seqno_last_used(&self) -> u64 {
        self.vmpck0_seqno
    }

    /// Increase the VMPCK0 sequence number by two. In order to keep the
    /// sequence number in-sync with the PSP, this is called only when the
    /// `SNP_GUEST_REQUEST` response is received.
    fn seqno_add_two(&mut self) {
        self.vmpck0_seqno += 2;
    }

    /// Set the user_extdata_size to `n` and clear the first `n` bytes from `ext_data`
    pub fn set_user_extdata_size(&mut self, n: usize) -> Result<(), SvsmReqError> {
        // At least one page
        if (n >> PAGE_SHIFT) == 0 {
            return Err(SvsmReqError::invalid_parameter());
        }
        self.ext_data.nclear(n)?;
        self.user_extdata_size = n;

        Ok(())
    }

    /// Call the GHCB layer to send the encrypted SNP_GUEST_REQUEST message
    /// to the PSP.
    fn send(&mut self, req_class: SnpGuestRequestClass) -> Result<(), SvsmReqError> {
        let req_page = self.request.addr();
        let resp_page = self.response.addr();
        let data_pages = self.ext_data.addr();
        let ghcb = current_ghcb();

        if req_class == SnpGuestRequestClass::Extended {
            let num_user_pages = (self.user_extdata_size >> PAGE_SHIFT) as u64;
            ghcb.guest_ext_request(req_page, resp_page, data_pages, num_user_pages)?;
        } else {
            ghcb.guest_request(req_page, resp_page)?;
        }

        self.seqno_add_two();

        Ok(())
    }

    // Encrypt the request message from encrypted memory
    fn encrypt_request(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
        buffer: &[u8],
        command_len: usize,
    ) -> Result<(), SvsmReqError> {
        // VMPL0 `SNP_GUEST_REQUEST` commands are encrypted with the VMPCK0 key
        let vmpck0: [u8; VMPCK_SIZE] = secrets_page().get_vmpck(0);

        let inbuf = buffer
            .get(..command_len)
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // For security reasons, encrypt the message in protected memory (staging)
        // and then copy the result to shared memory (request)
        self.staging
            .encrypt_set(msg_type, msg_seqno, &vmpck0, inbuf)?;
        self.request.write_from(&self.staging);
        Ok(())
    }

    // Decrypt the response message from encrypted memory
    fn decrypt_response(
        &mut self,
        msg_seqno: u64,
        msg_type: SnpGuestRequestMsgType,
        buffer: &mut [u8],
    ) -> Result<usize, SvsmReqError> {
        let vmpck0: [u8; VMPCK_SIZE] = secrets_page().get_vmpck(0);

        // For security reasons, decrypt the message in protected memory (staging)
        self.response.read_into(&mut self.staging);
        let result = self
            .staging
            .decrypt_get(msg_type, msg_seqno, &vmpck0, buffer);

        if let Err(e) = result {
            match e {
                // The buffer provided is too small to store the unwrapped response.
                // There is no need to clear the VMPCK0, just report it as invalid parameter.
                SvsmReqError::RequestError(SvsmResultCode::INVALID_PARAMETER) => (),
                _ => secrets_page_mut().clear_vmpck(0),
            }
        }

        result
    }

    /// Send the provided VMPL0 `SNP_GUEST_REQUEST` command to the PSP.
    ///
    /// The command will be encrypted using AES-256 GCM.
    ///
    /// # Arguments
    ///
    /// * `req_class`: whether this is a regular or extended `SNP_GUEST_REQUEST` command
    /// * `msg_type`: type of the command stored in `buffer`, e.g. SNP_MSG_REPORT_REQ
    /// * `buffer`: buffer with the `SNP_GUEST_REQUEST` command to be sent.
    ///             The same buffer will also be used to store the response.
    /// * `command_len`: Size (in bytes) of the command stored in `buffer`
    ///
    /// # Returns
    ///
    /// * Success:
    ///     * `usize`: Size (in bytes) of the response stored in `buffer`
    /// * Error:
    ///     * [`SvsmReqError`]
    fn send_request(
        &mut self,
        req_class: SnpGuestRequestClass,
        msg_type: SnpGuestRequestMsgType,
        buffer: &mut [u8],
        command_len: usize,
    ) -> Result<usize, SvsmReqError> {
        if secrets_page().is_vmpck_clear(0) {
            return Err(SvsmReqError::invalid_request());
        }

        // Message sequence number overflow, the driver will not able
        // to send subsequent `SNP_GUEST_REQUEST` messages to the PSP.
        // The sequence number is restored only when the guest is rebooted.
        let Some(msg_seqno) = self.seqno_last_used().checked_add(1) else {
            log::error!("SNP_GUEST_REQUEST: sequence number overflow");
            secrets_page_mut().clear_vmpck(0);
            return Err(SvsmReqError::invalid_request());
        };

        self.encrypt_request(msg_type, msg_seqno, buffer, command_len)?;

        if let Err(e) = self.send(req_class) {
            if let SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(_rbx, info2))) =
                e
            {
                // For some reason the hypervisor did not forward the request to the PSP.
                //
                // Because the message sequence number is used as part of the AES-GCM IV, it is important that the
                // guest retry the request before allowing another request to be performed so that the IV cannot be
                // reused on a new message payload.
                match info2 & 0xffff_ffff_0000_0000u64 {
                    // The certificate buffer provided is too small.
                    SNP_GUEST_REQ_INVALID_LEN => {
                        if req_class == SnpGuestRequestClass::Extended {
                            if let Err(e1) = self.send(SnpGuestRequestClass::Regular) {
                                log::error!(
                                    "SNP_GUEST_REQ_INVALID_LEN. Aborting, request resend failed"
                                );
                                secrets_page_mut().clear_vmpck(0);
                                return Err(e1);
                            }
                            return Err(e);
                        } else {
                            // We sent a regular SNP_GUEST_REQUEST, but the hypervisor returned
                            // an error code that is exclusive for extended SNP_GUEST_REQUEST
                            secrets_page_mut().clear_vmpck(0);
                            return Err(SvsmReqError::invalid_request());
                        }
                    }
                    // The hypervisor is busy.
                    SNP_GUEST_REQ_ERR_BUSY => {
                        if let Err(e2) = self.send(req_class) {
                            log::error!("SNP_GUEST_REQ_ERR_BUSY. Aborting, request resend failed");
                            secrets_page_mut().clear_vmpck(0);
                            return Err(e2);
                        }
                        // ... request resend worked, continue normally.
                    }
                    // Failed for unknown reason. Status codes can be found in
                    // the AMD SEV-SNP spec or in the linux kernel include/uapi/linux/psp-sev.h
                    _ => {
                        log::error!("SNP_GUEST_REQUEST failed, unknown error code={}\n", info2);
                        secrets_page_mut().clear_vmpck(0);
                        return Err(e);
                    }
                }
            }
        }

        let msg_seqno = self.seqno_last_used();
        let resp_msg_type = SnpGuestRequestMsgType::try_from(msg_type as u8 + 1)?;

        self.decrypt_response(msg_seqno, resp_msg_type, buffer)
    }

    /// Send the provided regular `SNP_GUEST_REQUEST` command to the PSP
    pub fn send_regular_guest_request(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        buffer: &mut [u8],
        command_len: usize,
    ) -> Result<usize, SvsmReqError> {
        self.send_request(SnpGuestRequestClass::Regular, msg_type, buffer, command_len)
    }

    /// Send the provided extended `SNP_GUEST_REQUEST` command to the PSP
    pub fn send_extended_guest_request(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        buffer: &mut [u8],
        command_len: usize,
        certs: &mut [u8],
    ) -> Result<usize, SvsmReqError> {
        self.set_user_extdata_size(certs.len())?;

        let outbuf_len: usize = self.send_request(
            SnpGuestRequestClass::Extended,
            msg_type,
            buffer,
            command_len,
        )?;

        // The SEV-SNP certificates can be used to verify the attestation report.
        self.ext_data.copy_to_slice(certs)?;
        // At this point, a zeroed ext_data buffer indicates that the
        // certificates were not imported. The VM owner can import them from the
        // host using the virtee/snphost project
        if certs[..24] == [0; 24] {
            log::warn!("SEV-SNP certificates not found. Make sure they were loaded from the host.");
        }

        Ok(outbuf_len)
    }
}

/// Initialize the global `SnpGuestRequestDriver`
///
/// # Panics
///
/// This function panics if we fail to initialize any of the `SnpGuestRequestDriver` fields.
pub fn guest_request_driver_init() {
    let cell = GREQ_DRIVER.lock();
    let _ = cell.get_or_init(|| {
        SnpGuestRequestDriver::new().expect("SnpGuestRequestDriver failed to initialize")
    });
}

/// Send the provided regular `SNP_GUEST_REQUEST` command to the PSP.
/// Further details can be found in the `SnpGuestRequestDriver.send_request()` documentation.
pub fn send_regular_guest_request(
    msg_type: SnpGuestRequestMsgType,
    buffer: &mut [u8],
    request_len: usize,
) -> Result<usize, SvsmReqError> {
    let mut cell = GREQ_DRIVER.lock();
    let driver: &mut SnpGuestRequestDriver =
        cell.get_mut().ok_or_else(SvsmReqError::invalid_request)?;
    driver.send_regular_guest_request(msg_type, buffer, request_len)
}

/// Send the provided extended `SNP_GUEST_REQUEST` command to the PSP
/// Further details can be found in the `SnpGuestRequestDriver.send_request()` documentation.
pub fn send_extended_guest_request(
    msg_type: SnpGuestRequestMsgType,
    buffer: &mut [u8],
    request_len: usize,
    certs: &mut [u8],
) -> Result<usize, SvsmReqError> {
    let mut cell = GREQ_DRIVER.lock();
    let driver: &mut SnpGuestRequestDriver =
        cell.get_mut().ok_or_else(SvsmReqError::invalid_request)?;
    driver.send_extended_guest_request(msg_type, buffer, request_len, certs)
}
