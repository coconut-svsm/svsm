// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Message that carries an encrypted `SNP_GUEST_REQUEST` command in the payload

extern crate alloc;

use alloc::{
    alloc::{alloc_zeroed, Layout},
    boxed::Box,
};
use core::{
    mem::size_of,
    ptr::addr_of,
    slice::{from_raw_parts, from_raw_parts_mut, from_ref},
};

use crate::{
    address::{Address, VirtAddr},
    cpu::percpu::this_cpu_mut,
    crypto::aead::{Aes256Gcm, Aes256GcmTrait, AUTHTAG_SIZE, IV_SIZE},
    mm::virt_to_phys,
    protocols::errors::SvsmReqError,
    sev::{ghcb::PageStateChangeOp, secrets_page::VMPCK_SIZE},
    types::{PageSize, PAGE_SIZE},
};

// Message Header Format (AMD SEV-SNP spec. table 98)

/// Version of the message header
const HDR_VERSION: u8 = 1;
/// Version of the message payload
const MSG_VERSION: u8 = 1;

/// AEAD Algorithm Encodings (AMD SEV-SNP spec. table 99)
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum SnpGuestRequestAead {
    Invalid = 0,
    Aes256Gcm = 1,
}

/// Message Type Encodings (AMD SEV-SNP spec. table 100)
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum SnpGuestRequestMsgType {
    Invalid = 0,
    ReportRequest = 5,
    ReportResponse = 6,
}

impl TryFrom<u8> for SnpGuestRequestMsgType {
    type Error = SvsmReqError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == SnpGuestRequestMsgType::Invalid as u8 => Ok(SnpGuestRequestMsgType::Invalid),
            x if x == SnpGuestRequestMsgType::ReportRequest as u8 => {
                Ok(SnpGuestRequestMsgType::ReportRequest)
            }
            x if x == SnpGuestRequestMsgType::ReportResponse as u8 => {
                Ok(SnpGuestRequestMsgType::ReportResponse)
            }
            _ => Err(SvsmReqError::invalid_parameter()),
        }
    }
}

/// Message header size
const MSG_HDR_SIZE: usize = size_of::<SnpGuestRequestMsgHdr>();
/// Message payload size
const MSG_PAYLOAD_SIZE: usize = PAGE_SIZE - MSG_HDR_SIZE;

/// Maximum buffer size that the hypervisor takes to store the
/// SEV-SNP certificates
pub const SNP_GUEST_REQ_MAX_DATA_SIZE: usize = 4 * PAGE_SIZE;

/// `SNP_GUEST_REQUEST` message header format
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SnpGuestRequestMsgHdr {
    /// Message authentication tag
    authtag: [u8; 32],
    /// The sequence number for this message
    msg_seqno: u64,
    /// Reserve. Must be zero.
    rsvd1: [u8; 8],
    /// The AEAD used to encrypt this message
    algo: u8,
    /// The version of the message header
    hdr_version: u8,
    /// The size of the message header in bytes
    hdr_sz: u16,
    /// The type of the payload
    msg_type: u8,
    /// The version of the payload
    msg_version: u8,
    /// The size of the payload in bytes
    msg_sz: u16,
    /// Reserved. Must be zero.
    rsvd2: u32,
    /// The ID of the VMPCK used to protect this message
    msg_vmpck: u8,
    /// Reserved. Must be zero.
    rsvd3: [u8; 35],
}

impl SnpGuestRequestMsgHdr {
    /// Allocate a new [`SnpGuestRequestMsgHdr`] and initialize it
    ///
    /// # Panic
    ///
    /// * [`SnpGuestRequestMsgHdr`] size does not fit in a u16.
    pub fn new(msg_sz: u16, msg_type: SnpGuestRequestMsgType, msg_seqno: u64) -> Self {
        assert!(u16::try_from(MSG_HDR_SIZE).is_ok());

        Self {
            msg_seqno,
            algo: SnpGuestRequestAead::Aes256Gcm as u8,
            hdr_version: HDR_VERSION,
            hdr_sz: MSG_HDR_SIZE as u16,
            msg_type: msg_type as u8,
            msg_version: MSG_VERSION,
            msg_sz,
            msg_vmpck: 0,
            ..Default::default()
        }
    }

    /// Set the authenticated tag
    fn set_authtag(&mut self, new_tag: &[u8]) -> Result<(), SvsmReqError> {
        self.authtag
            .get_mut(..new_tag.len())
            .ok_or_else(SvsmReqError::invalid_parameter)?
            .copy_from_slice(new_tag);
        Ok(())
    }

    /// Validate the [`SnpGuestRequestMsgHdr`] fields
    fn validate(
        &self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
    ) -> Result<(), SvsmReqError> {
        let header_size =
            u16::try_from(MSG_HDR_SIZE).map_err(|_| SvsmReqError::invalid_format())?;
        if self.hdr_version != HDR_VERSION
            || self.hdr_sz != header_size
            || self.algo != SnpGuestRequestAead::Aes256Gcm as u8
            || self.msg_type != msg_type as u8
            || self.msg_vmpck != 0
            || self.msg_seqno != msg_seqno
        {
            return Err(SvsmReqError::invalid_format());
        }
        Ok(())
    }

    /// Get a slice of the header fields used as additional authenticated data (AAD)
    fn get_aad_slice(&self) -> &[u8] {
        let self_gva = addr_of!(*self);
        let algo_gva = addr_of!(self.algo);
        let algo_offset = algo_gva as isize - self_gva as isize;

        let slice: &[Self] = from_ref(self);
        let ptr: *const Self = slice.as_ptr();
        // SAFETY: we are doing:
        // &[Self] -> *const Self -> *const u8 -> &[u8]
        // This is safe as it simply reinterprets the underlying type as bytes
        // by using the &self borrow. This is safe because Self has no invalid
        // representations, as it is composed of simple integer types.
        // &[u8] has no alignment requirements, and this new slice has the
        // same size as Self, so we are within bounds.
        let b = unsafe { from_raw_parts(ptr.cast::<u8>(), size_of::<Self>()) };

        &b[algo_offset as usize..]
    }

    /// Get [`SnpGuestRequestMsgHdr`] as a mutable slice reference
    fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self as *mut _ as *mut u8, MSG_HDR_SIZE) }
    }
}

impl Default for SnpGuestRequestMsgHdr {
    /// default() method implementation. We can't derive Default because
    /// the field "rsvd3: [u8; 35]" conflicts with the Default trait, which
    /// supports up to [T; 32].
    fn default() -> Self {
        Self {
            authtag: [0; 32],
            msg_seqno: 0,
            rsvd1: [0; 8],
            algo: 0,
            hdr_version: 0,
            hdr_sz: 0,
            msg_type: 0,
            msg_version: 0,
            msg_sz: 0,
            rsvd2: 0,
            msg_vmpck: 0,
            rsvd3: [0; 35],
        }
    }
}

/// `SNP_GUEST_REQUEST` message format
#[repr(C, align(4096))]
#[derive(Clone, Copy, Debug)]
pub struct SnpGuestRequestMsg {
    hdr: SnpGuestRequestMsgHdr,
    pld: [u8; MSG_PAYLOAD_SIZE],
}

impl SnpGuestRequestMsg {
    /// Allocate the object in the heap without going through stack as
    /// this is a large object
    ///
    /// # Panic
    ///
    /// * Memory allocated is not page aligned or Self does not
    ///   fit into a page
    pub fn boxed_new() -> Result<Box<Self>, SvsmReqError> {
        let layout = Layout::new::<Self>();

        // The GHCB spec says it has to fit in one page and be page aligned
        assert!(layout.size() <= PAGE_SIZE);

        unsafe {
            let addr = alloc_zeroed(layout);
            if addr.is_null() {
                return Err(SvsmReqError::invalid_request());
            }

            assert!(VirtAddr::from(addr).is_page_aligned());

            let ptr = addr.cast::<Self>();
            Ok(Box::from_raw(ptr))
        }
    }

    /// Clear the C-bit (memory encryption bit) for the Self page
    ///
    /// # Safety
    ///
    /// * The caller is responsible for setting the page back to encrypted
    ///   before the object is dropped. Shared pages should not be freed
    ///   (returned to the allocator)
    pub fn set_shared(&mut self) -> Result<(), SvsmReqError> {
        let vaddr = VirtAddr::from(self as *mut Self);
        this_cpu_mut()
            .get_pgtable()
            .set_shared_4k(vaddr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(vaddr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscShared,
            )
            .map_err(|_| SvsmReqError::invalid_request())
    }

    /// Set the C-bit (memory encryption bit) for the Self page
    pub fn set_encrypted(&mut self) -> Result<(), SvsmReqError> {
        let vaddr = VirtAddr::from(self as *mut Self);
        this_cpu_mut()
            .get_pgtable()
            .set_encrypted_4k(vaddr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(vaddr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscPrivate,
            )
            .map_err(|_| SvsmReqError::invalid_request())
    }

    /// Fill the [`SnpGuestRequestMsg`] fields with zeros
    pub fn clear(&mut self) {
        self.hdr.as_slice_mut().fill(0);
        self.pld.fill(0);
    }

    /// Encrypt the provided `SNP_GUEST_REQUEST` command and store the result in the actual message payload
    ///
    /// The command will be encrypted using AES-256 GCM and part of the message header will be
    /// used as additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `msg_type`: Type of the command stored in the `command` buffer.
    /// * `msg_seqno`: VMPL0 sequence number to be used in the message. The PSP will reject
    ///                subsequent messages when it detects that the sequence numbers are
    ///                out of sync. The sequence number is also used as initialization
    ///                vector (IV) in encryption.
    /// * `vmpck0`: VMPCK0 key that will be used to encrypt the command.
    /// * `command`: command slice to be encrypted.
    ///
    /// # Returns
    ///
    /// () on success and [`SvsmReqError`] on error.
    ///
    /// # Panic
    ///
    /// * The command length does not fit in a u16
    /// * The encrypted and the original command don't have the same size
    pub fn encrypt_set(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
        vmpck0: &[u8; VMPCK_SIZE],
        command: &[u8],
    ) -> Result<(), SvsmReqError> {
        let payload_size_u16 =
            u16::try_from(command.len()).map_err(|_| SvsmReqError::invalid_parameter())?;

        let mut msg_hdr = SnpGuestRequestMsgHdr::new(payload_size_u16, msg_type, msg_seqno);
        let aad: &[u8] = msg_hdr.get_aad_slice();
        let iv: [u8; IV_SIZE] = build_iv(msg_seqno);

        self.pld.fill(0);

        // Encrypt the provided command and store the result in the message payload
        let authtag_end: usize = Aes256Gcm::encrypt(&iv, vmpck0, aad, command, &mut self.pld)?;

        // In the Aes256Gcm encrypt API, the authtag is postfixed (comes after the encrypted payload)
        let ciphertext_end: usize = authtag_end - AUTHTAG_SIZE;
        let authtag = self
            .pld
            .get_mut(ciphertext_end..authtag_end)
            .ok_or_else(SvsmReqError::invalid_request)?;

        // The command should have the same size when encrypted and decrypted
        assert_eq!(command.len(), ciphertext_end);

        // Move the authtag to the message header
        msg_hdr.set_authtag(authtag)?;
        authtag.fill(0);

        self.hdr = msg_hdr;

        Ok(())
    }

    /// Decrypt the `SNP_GUEST_REQUEST` command stored in the message and store the decrypted command in
    /// the provided `outbuf`.
    ///
    /// The command stored in the message payload is usually a response command received from the PSP.
    /// It will be decrypted using AES-256 GCM and part of the message header will be used as
    /// additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `msg_type`: Type of the command stored in the message payload
    /// * `msg_seqno`: VMPL0 sequence number that was used in the message.
    /// * `vmpck0`: VMPCK0 key, it will be used to decrypt the message
    /// * `outbuf`: buffer that will be used to store the decrypted message payload
    ///
    /// # Returns
    ///
    /// * Success
    ///     * usize: Number of bytes written to `outbuf`
    /// * Error
    ///     * [`SvsmReqError`]
    pub fn decrypt_get(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
        vmpck0: &[u8; VMPCK_SIZE],
        outbuf: &mut [u8],
    ) -> Result<usize, SvsmReqError> {
        self.hdr.validate(msg_type, msg_seqno)?;

        let iv: [u8; IV_SIZE] = build_iv(msg_seqno);
        let aad: &[u8] = self.hdr.get_aad_slice();

        // In the Aes256Gcm decrypt API, the authtag must be provided postfix in the inbuf
        let ciphertext_end = usize::from(self.hdr.msg_sz);
        let tag_end: usize = ciphertext_end + AUTHTAG_SIZE;

        // The message payload must be large enough to hold the ciphertext and
        // the authentication tag.
        let hdr_tag = self
            .hdr
            .authtag
            .get(..AUTHTAG_SIZE)
            .ok_or_else(SvsmReqError::invalid_request)?;
        let pld_tag = self
            .pld
            .get_mut(ciphertext_end..tag_end)
            .ok_or_else(SvsmReqError::invalid_request)?;
        pld_tag.copy_from_slice(hdr_tag);

        // Payload with postfixed authtag
        let inbuf = self
            .pld
            .get(..tag_end)
            .ok_or_else(SvsmReqError::invalid_request)?;

        let outbuf_len: usize = Aes256Gcm::decrypt(&iv, vmpck0, aad, inbuf, outbuf)?;

        Ok(outbuf_len)
    }
}

/// Build the initialization vector for AES-256 GCM
fn build_iv(msg_seqno: u64) -> [u8; IV_SIZE] {
    const U64_SIZE: usize = size_of::<u64>();
    let mut iv = [0u8; IV_SIZE];

    iv[..U64_SIZE].copy_from_slice(&msg_seqno.to_ne_bytes());
    iv
}

/// Set to encrypted all the 4k pages of a memory range
fn set_encrypted_region_4k(start: VirtAddr, end: VirtAddr) -> Result<(), SvsmReqError> {
    for addr in (start.bits()..end.bits())
        .step_by(PAGE_SIZE)
        .map(VirtAddr::from)
    {
        this_cpu_mut()
            .get_pgtable()
            .set_encrypted_4k(addr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(addr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscPrivate,
            )
            .map_err(|_| SvsmReqError::invalid_request())?;
    }
    Ok(())
}

/// Set to shared all the 4k pages of a memory range
fn set_shared_region_4k(start: VirtAddr, end: VirtAddr) -> Result<(), SvsmReqError> {
    for addr in (start.bits()..end.bits())
        .step_by(PAGE_SIZE)
        .map(VirtAddr::from)
    {
        this_cpu_mut()
            .get_pgtable()
            .set_shared_4k(addr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(addr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscShared,
            )
            .map_err(|_| SvsmReqError::invalid_request())?;
    }
    Ok(())
}

/// Data page(s) the hypervisor will use to store certificate data in
/// an extended `SNP_GUEST_REQUEST`
#[repr(C, align(4096))]
#[derive(Debug)]
pub struct SnpGuestRequestExtData {
    /// According to the GHCB spec, the data page(s) must be contiguous pages if
    /// supplying more than one page and all certificate pages must be
    /// assigned to the hypervisor (shared).
    data: [u8; SNP_GUEST_REQ_MAX_DATA_SIZE],
}

impl SnpGuestRequestExtData {
    /// Allocate the object in the heap without going through stack as
    /// this is a large object
    pub fn boxed_new() -> Result<Box<Self>, SvsmReqError> {
        let layout = Layout::new::<Self>();
        unsafe {
            let addr = alloc_zeroed(layout);
            if addr.is_null() {
                return Err(SvsmReqError::invalid_request());
            }
            assert!(VirtAddr::from(addr).is_page_aligned());

            let ptr = addr.cast::<Self>();
            Ok(Box::from_raw(ptr))
        }
    }

    /// Clear the C-bit (memory encryption bit) for the Self pages
    ///
    /// # Safety
    ///
    /// * The caller is responsible for setting the page back to encrypted
    ///   before the object is dropped. Shared pages should not be freed
    ///   (returned to the allocator)
    pub fn set_shared(&mut self) -> Result<(), SvsmReqError> {
        const EXT_DATA_SIZE: usize = size_of::<SnpGuestRequestExtData>();

        let start = VirtAddr::from(self as *mut Self);
        let end = start + EXT_DATA_SIZE;
        set_shared_region_4k(start, end)
    }

    /// Set the C-bit (memory encryption bit) for the Self pages
    pub fn set_encrypted(&mut self) -> Result<(), SvsmReqError> {
        const EXT_DATA_SIZE: usize = size_of::<SnpGuestRequestExtData>();

        let start = VirtAddr::from(self as *mut Self);
        let end = start + EXT_DATA_SIZE;
        set_encrypted_region_4k(start, end)
    }

    /// Clear the first `n` bytes from data
    pub fn nclear(&mut self, n: usize) -> Result<(), SvsmReqError> {
        self.data
            .get_mut(..n)
            .ok_or_else(SvsmReqError::invalid_parameter)?
            .fill(0);
        Ok(())
    }

    /// Fill up the `outbuf` slice provided with bytes from data
    pub fn copy_to_slice(&self, outbuf: &mut [u8]) -> Result<(), SvsmReqError> {
        let data = self
            .data
            .get(..outbuf.len())
            .ok_or_else(SvsmReqError::invalid_parameter)?;
        outbuf.copy_from_slice(data);
        Ok(())
    }

    /// Check if the first `n` bytes from data are zeroed
    pub fn is_nclear(&self, n: usize) -> Result<bool, SvsmReqError> {
        let data = self
            .data
            .get(..n)
            .ok_or_else(SvsmReqError::invalid_parameter)?;
        Ok(data.iter().all(|e| *e == 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::alloc::{TestRootMem, DEFAULT_TEST_MEMORY_SIZE};
    use crate::sev::secrets_page::VMPCK_SIZE;

    #[test]
    fn test_requestmsg_boxed_new() {
        let _mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut data = SnpGuestRequestMsg::boxed_new().unwrap();
        assert!(data.hdr.as_slice_mut().iter().all(|c| *c == 0));
        assert!(data.pld.iter().all(|c| *c == 0));
    }

    #[test]
    fn test_reqextdata_boxed_new() {
        let _mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let data = SnpGuestRequestExtData::boxed_new().unwrap();
        assert!(data.data.iter().all(|c| *c == 0));
    }

    #[test]
    fn u16_from_guest_msg_hdr_size() {
        assert!(u16::try_from(MSG_HDR_SIZE).is_ok());
    }

    #[test]
    fn aad_size() {
        let hdr = SnpGuestRequestMsgHdr::default();
        let aad = hdr.get_aad_slice();

        const HDR_ALGO_OFFSET: usize = 48;

        assert_eq!(aad.len(), MSG_HDR_SIZE - HDR_ALGO_OFFSET);
    }

    #[test]
    fn encrypt_decrypt_payload() {
        let mut msg = SnpGuestRequestMsg {
            hdr: SnpGuestRequestMsgHdr::default(),
            pld: [0; MSG_PAYLOAD_SIZE],
        };

        const PLAINTEXT: &[u8] = b"request-to-be-encrypted";
        let vmpck0 = [5u8; VMPCK_SIZE];
        let vmpck0_seqno: u64 = 1;

        let result = msg.encrypt_set(
            SnpGuestRequestMsgType::ReportRequest,
            vmpck0_seqno,
            &vmpck0,
            PLAINTEXT,
        );

        assert!(result.is_ok());

        let mut outbuf = [0u8; PLAINTEXT.len()];

        let result = msg.decrypt_get(
            SnpGuestRequestMsgType::ReportRequest,
            vmpck0_seqno,
            &vmpck0,
            &mut outbuf,
        );

        assert!(result.is_ok());

        let outbuf_len = result.unwrap();
        assert_eq!(outbuf_len, PLAINTEXT.len());

        assert_eq!(outbuf, PLAINTEXT);
    }
}
