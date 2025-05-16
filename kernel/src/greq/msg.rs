// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Message that carries an encrypted `SNP_GUEST_REQUEST` command in the payload

use core::mem::{offset_of, size_of};

use crate::{
    crypto::aead::{Aes256Gcm, Aes256GcmTrait, AUTHTAG_SIZE, IV_SIZE},
    protocols::errors::SvsmReqError,
    sev::secrets_page::VMPCK_SIZE,
    types::PAGE_SIZE,
};

use zerocopy::{FromBytes, Immutable, IntoBytes};

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
            x if x == Self::Invalid as u8 => Ok(Self::Invalid),
            x if x == Self::ReportRequest as u8 => Ok(Self::ReportRequest),
            x if x == Self::ReportResponse as u8 => Ok(Self::ReportResponse),
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

/// `SNP_GUEST_REQUEST` message header format (AMD SEV-SNP spec. table 98)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
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

const _: () = assert!(size_of::<SnpGuestRequestMsgHdr>() <= u16::MAX as usize);

impl SnpGuestRequestMsgHdr {
    /// Allocate a new [`SnpGuestRequestMsgHdr`] and initialize it
    pub fn new(msg_sz: u16, msg_type: SnpGuestRequestMsgType, msg_seqno: u64) -> Self {
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
        if self.hdr_version != HDR_VERSION
            || self.hdr_sz != MSG_HDR_SIZE as u16
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
        let algo_offset = offset_of!(Self, algo);
        &self.as_bytes()[algo_offset..]
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
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct SnpGuestRequestMsg {
    hdr: SnpGuestRequestMsgHdr,
    pld: [u8; MSG_PAYLOAD_SIZE],
}

// The GHCB spec says it has to fit in one page and be page aligned
const _: () = assert!(size_of::<SnpGuestRequestMsg>() <= PAGE_SIZE);

impl SnpGuestRequestMsg {
    /// Encrypt the provided `SNP_GUEST_REQUEST` command and store the result in the actual message payload
    ///
    /// The command will be encrypted using AES-256 GCM and part of the message header will be
    /// used as additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `msg_type`: Type of the command stored in the `command` buffer.
    /// * `msg_seqno`: VMPL0 sequence number to be used in the message. The PSP will reject
    ///   subsequent messages when it detects that the sequence numbers are
    ///   out of sync. The sequence number is also used as initialization
    ///   vector (IV) in encryption.
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

/// Data page(s) the hypervisor will use to store certificate data in
/// an extended `SNP_GUEST_REQUEST`
pub type SnpGuestRequestExtData = [u8; SNP_GUEST_REQ_MAX_DATA_SIZE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snp_guest_request_hdr_offsets() {
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, authtag), 0);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_seqno), 0x20);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, rsvd1), 0x28);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, algo), 0x30);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, hdr_version), 0x31);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, hdr_sz), 0x32);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_type), 0x34);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_version), 0x35);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_sz), 0x36);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, rsvd2), 0x38);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_vmpck), 0x3c);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, rsvd3), 0x3d);
    }

    #[test]
    fn test_snp_guest_request_msg_offsets() {
        assert_eq!(offset_of!(SnpGuestRequestMsg, hdr), 0);
        assert_eq!(offset_of!(SnpGuestRequestMsg, pld), 0x60);
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

        msg.encrypt_set(
            SnpGuestRequestMsgType::ReportRequest,
            vmpck0_seqno,
            &vmpck0,
            PLAINTEXT,
        )
        .unwrap();

        let mut outbuf = [0u8; PLAINTEXT.len()];

        let outbuf_len = msg
            .decrypt_get(
                SnpGuestRequestMsgType::ReportRequest,
                vmpck0_seqno,
                &vmpck0,
                &mut outbuf,
            )
            .unwrap();

        assert_eq!(outbuf_len, PLAINTEXT.len());

        assert_eq!(outbuf, PLAINTEXT);
    }
}
