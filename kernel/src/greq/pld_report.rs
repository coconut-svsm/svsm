// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! `SNP_GUEST_REQUEST` command to request an attestation report.

use core::mem::size_of;

use crate::protocols::errors::SvsmReqError;

/// Size of the `SnpReportRequest.user_data`
pub const USER_DATA_SIZE: usize = 64;

/// MSG_REPORT_REQ payload format (AMD SEV-SNP spec. table 20)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SnpReportRequest {
    /// Guest-provided data to be included in the attestation report
    /// REPORT_DATA (512 bits)
    user_data: [u8; USER_DATA_SIZE],
    /// The VMPL to put in the attestation report
    vmpl: u32,
    /// 31:2 - Reserved
    ///  1:0 - KEY_SEL. Selects which key to use for derivation
    ///        0: If VLEK is installed, sign with VLEK. Otherwise, sign with VCEK
    ///        1: Sign with VCEK
    ///        2: Sign with VLEK
    ///        3: Reserved
    flags: u32,
    /// Reserved, must be zero
    rsvd: [u8; 24],
}

impl SnpReportRequest {
    /// Take a slice and return a reference for Self
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let buffer = buffer
            .get(..size_of::<Self>())
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // SAFETY: SnpReportRequest has no invalid representations, as it is
        // comprised entirely of integer types. It is repr(packed), so its
        // required alignment is simply 1. We have checked the size, so this
        // is entirely safe.
        let request = unsafe { &*buffer.as_ptr().cast::<Self>() };

        if !request.is_reserved_clear() {
            return Err(SvsmReqError::invalid_parameter());
        }
        Ok(request)
    }

    pub fn is_vmpl0(&self) -> bool {
        self.vmpl == 0
    }

    /// Check if the reserved field is clear
    fn is_reserved_clear(&self) -> bool {
        self.rsvd.into_iter().all(|e| e == 0)
    }
}

///  MSG_REPORT_RSP payload format (AMD SEV-SNP spec. table 23)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SnpReportResponse {
    /// The status of the key derivation operation, see [SnpReportResponseStatus]
    status: u32,
    /// Size in bytes of the report
    report_size: u32,
    /// Reserved
    _reserved: [u8; 24],
    /// The attestation report generated by firmware
    report: AttestationReport,
}

/// Supported values for SnpReportResponse.status
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum SnpReportResponseStatus {
    Success = 0,
    InvalidParameters = 0x16,
    InvalidKeySelection = 0x27,
}

impl SnpReportResponse {
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let buffer = buffer
            .get(..size_of::<Self>())
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // SAFETY: SnpReportResponse has no invalid representations, as it is
        // comprised entirely of integer types. It is repr(packed), so its
        // required alignment is simply 1. We have checked the size, so this
        // is entirely safe.
        let response = unsafe { &*buffer.as_ptr().cast::<Self>() };
        Ok(response)
    }

    /// Validate the [SnpReportResponse] fields
    pub fn validate(&self) -> Result<(), SvsmReqError> {
        if self.status != SnpReportResponseStatus::Success as u32 {
            return Err(SvsmReqError::invalid_request());
        }

        if self.report_size != size_of::<AttestationReport>() as u32 {
            return Err(SvsmReqError::invalid_format());
        }

        Ok(())
    }

    pub fn get_report(&self) -> &AttestationReport {
          &self.report
    }

    pub fn get_report_size(&self) -> u32 {
          self.report_size
    }
}

/// The `TCB_VERSION` contains the security version numbers of each
/// component in the trusted computing base (TCB) of the SNP firmware.
/// (AMD SEV-SNP spec. table 3)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct TcbVersion {
    /// Version of the Microcode, SNP firmware, PSP and boot loader
    raw: u64,
}

/// Format for an ECDSA P-384 with SHA-384 signature (AMD SEV-SNP spec. table 115)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct Signature {
    /// R component of this signature
    r: [u8; 72],
    /// S component of this signature
    s: [u8; 72],
    /// Reserved
    reserved: [u8; 368],
}

/// ATTESTATION_REPORT format (AMD SEV-SNP spec. table 21)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct AttestationReport {
    /// Version number of this attestation report
    version: u32,
    /// The guest SVN
    guest_svn: u32,
    /// The guest policy
    policy: u64,
    /// The family ID provided at launch
    family_id: [u8; 16],
    /// The image ID provided at launch
    image_id: [u8; 16],
    /// The request VMPL for the attestation report
    vmpl: u32,
    /// The signature algorithm used to sign this report
    signature_algo: u32,
    /// CurrentTcb
    platform_version: TcbVersion,
    /// Information about the platform
    platform_info: u64,
    /// Flags
    flags: u32,
    /// Reserved, must be zero
    reserved0: u32,
    /// Guest-provided data
    report_data: [u8; 64],
    /// The measurement calculated at launch
    measurement: [u8; 48],
    /// Data provided by the hypervisor at launch
    host_data: [u8; 32],
    /// SHA-384 digest of the ID public key that signed the ID block
    /// provided in `SNP_LAUNCH_FINISH`
    id_key_digest: [u8; 48],
    /// SHA-384 digest of the Author public key that certified the ID key,
    /// if provided in `SNP_LAUNCH_FINISH`. Zeroes if `AUTHOR_KEY_EN` is 1
    author_key_digest: [u8; 48],
    /// Report ID of this guest
    report_id: [u8; 32],
    /// Report ID of this guest's migration agent
    report_id_ma: [u8; 32],
    /// Report TCB version used to derive the VCEK that signed this report
    reported_tcb: TcbVersion,
    /// Reserved
    reserved1: [u8; 24],
    /// If `MaskChipId` is set to 0, Identifier unique to the chip as
    /// output by `GET_ID`. Otherwise, set to 0h
    chip_id: [u8; 64],
    /// Reserved and some more flags
    reserved2: [u8; 192],
    /// Signature of bytes 0h to 29Fh inclusive of this report
    signature: Signature,
}

const _: () = assert!(size_of::<AttestationReport>() <= u32::MAX as usize);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn test_snp_report_request_offsets() {
        assert_eq!(offset_of!(SnpReportRequest, user_data), 0x0);
        assert_eq!(offset_of!(SnpReportRequest, vmpl), 0x40);
        assert_eq!(offset_of!(SnpReportRequest, flags), 0x44);
        assert_eq!(offset_of!(SnpReportRequest, rsvd), 0x48);
    }

    #[test]
    fn test_snp_report_response_offsets() {
        assert_eq!(offset_of!(SnpReportResponse, status), 0x0);
        assert_eq!(offset_of!(SnpReportResponse, report_size), 0x4);
        assert_eq!(offset_of!(SnpReportResponse, _reserved), 0x8);
        assert_eq!(offset_of!(SnpReportResponse, report), 0x20);
    }

    #[test]
    fn test_ecdsa_p384_sha384_signature_offsets() {
        assert_eq!(offset_of!(Signature, r), 0x0);
        assert_eq!(offset_of!(Signature, s), 0x48);
        assert_eq!(offset_of!(Signature, reserved), 0x90);
    }

    #[test]
    fn test_attestation_report_offsets() {
        assert_eq!(offset_of!(AttestationReport, version), 0x0);
        assert_eq!(offset_of!(AttestationReport, guest_svn), 0x4);
        assert_eq!(offset_of!(AttestationReport, policy), 0x8);
        assert_eq!(offset_of!(AttestationReport, family_id), 0x10);
        assert_eq!(offset_of!(AttestationReport, image_id), 0x20);
        assert_eq!(offset_of!(AttestationReport, vmpl), 0x30);
        assert_eq!(offset_of!(AttestationReport, signature_algo), 0x34);
        assert_eq!(offset_of!(AttestationReport, platform_version), 0x38);
        assert_eq!(offset_of!(AttestationReport, platform_info), 0x40);
        assert_eq!(offset_of!(AttestationReport, flags), 0x48);
        assert_eq!(offset_of!(AttestationReport, reserved0), 0x4c);
        assert_eq!(offset_of!(AttestationReport, report_data), 0x50);
        assert_eq!(offset_of!(AttestationReport, measurement), 0x90);
        assert_eq!(offset_of!(AttestationReport, host_data), 0xc0);
        assert_eq!(offset_of!(AttestationReport, id_key_digest), 0xe0);
        assert_eq!(offset_of!(AttestationReport, author_key_digest), 0x110);
        assert_eq!(offset_of!(AttestationReport, report_id), 0x140);
        assert_eq!(offset_of!(AttestationReport, report_id_ma), 0x160);
        assert_eq!(offset_of!(AttestationReport, reported_tcb), 0x180);
        assert_eq!(offset_of!(AttestationReport, reserved1), 0x188);
        assert_eq!(offset_of!(AttestationReport, chip_id), 0x1a0);
        assert_eq!(offset_of!(AttestationReport, reserved2), 0x1e0);
        assert_eq!(offset_of!(AttestationReport, signature), 0x2a0);
    }
}
