// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025  Hewlett Packard Enterprise Development LP
// Copyright (c) 2025 Coconut-SVSM Authors
//

//! Attest protocol implementation

extern crate alloc;

use crate::address::{Address, PhysAddr};
use crate::crypto::digest::{Algorithm, Sha512};
use crate::error::{AttestError, SvsmError};
use crate::greq::services::get_extended_report;
use crate::greq::{
    pld_report::{SnpReportRequest, SnpReportResponse},
    services::get_regular_report,
};
use crate::mm::guestmem::{copy_slice_to_guest, read_bytes_from_guest, read_from_guest};
use crate::protocols::{RequestParams, errors::SvsmReqError};
use crate::utils::MemoryRegion;
#[cfg(all(feature = "vtpm", not(test)))]
use crate::vtpm::vtpm_get_manifest;

use alloc::{boxed::Box, vec::Vec};
use uuid::{Uuid, uuid};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::sev::ghcb::GhcbError;
use crate::types::PAGE_SHIFT;

pub const ATTEST_PROTOCOL_VERSION_MIN: u32 = 1;
pub const ATTEST_PROTOCOL_VERSION_MAX: u32 = 1;

const SERVICES_MANIFEST_GUID: Uuid = uuid!("63849ebb-3d92-4670-a1ff-58f9c94b87bb");
const GUID_HEADER_ENTRY_SIZE: usize = 24;
const SVSM_ATTEST_SERVICES: u32 = 0;
const SVSM_ATTEST_SINGLE_SERVICE: u32 = 1;

#[cfg(all(feature = "vtpm", not(test)))]
const SVSM_ATTEST_VTPM_GUID: Uuid = uuid!("c476f1eb-0123-45a5-9641-b4e7dde5bfe3");

// According to
// https://github.com/torvalds/linux/blob/155a3c003e555a7300d156a5252c004c392ec6b0/drivers/virt/coco/sev-guest/sev-guest.c#L370
// https://github.com/torvalds/linux/blob/155a3c003e555a7300d156a5252c004c392ec6b0/include/linux/psp-sev.h#L17
// the maximum size of the certificate buffer is 0x4000 bytes (16K).
// Could not find the  maximum size of the certificate buffer in the
// "Secure VM Service Module for SEV-SNP Guests, Revision 1.0",
// "SEV Secure Nested Paging Firmware ABI Specification, Revision 1.58"
// or "SEV-ES Guest-Hypervisor Communication Block Standardization, Revision 2.04"
// If future specifications update the maximum certificate buffer size, update the
// MAX_CERTIFICATE_SIZE constant below to match the new value.
const MAX_CERTIFICATE_SIZE: usize = 0x4000;

// Attest services operation structure, as defined in Table 11 of Secure VM Service Module for
// SEV-SNP Guests 58019 Rev, 1.00 July 2023
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
pub struct AttestServicesOp {
    report_gpa: u64,
    report_size: u32,
    reserved_1: [u8; 4],
    nonce_gpa: u64,
    nonce_size: u16,
    reserved_2: [u8; 6],
    manifest_gpa: u64,
    manifest_size: u32,
    reserved_3: [u8; 4],
    certificate_gpa: u64,
    certificate_size: u32,
    reserved_4: [u8; 4],
}

impl AttestServicesOp {
    /// Take a slice and return a reference for Self
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let ops: &Self =
            Self::ref_from_bytes(buffer).map_err(|_| SvsmReqError::invalid_parameter())?;
        if !ops.is_reserved_clear() {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok(ops)
    }

    /// Checks if reserved fields are all set to zero
    pub fn is_reserved_clear(&self) -> bool {
        self.reserved_1.iter().all(|&x| x == 0)
            && self.reserved_2.iter().all(|&x| x == 0)
            && self.reserved_3.iter().all(|&x| x == 0)
            && self.reserved_4.iter().all(|&x| x == 0)
    }

    /// Returns the nonce
    pub fn get_nonce(&self) -> Result<Vec<u8>, SvsmReqError> {
        // Check that nonce is the right size and doesn't cross a page boundary.
        // Nonce i.e. REPORT_DATA is 64 bytes per Table 22 of
        // "SEV Secure Nested Paging Firmware ABI Specification, Revision 1.57"
        let gpa = PhysAddr::from(self.nonce_gpa);
        let nonce_size = self.nonce_size.into();
        if nonce_size != 64 || gpa.crosses_page(nonce_size) {
            return Err(SvsmReqError::invalid_parameter());
        }

        read_bytes_from_guest(gpa, nonce_size).map_err(|_| SvsmReqError::invalid_parameter())
    }

    /// Returns the manifest buffer gpa and size
    /// Checks if gpa is page aligned and valid.
    /// Manifest buffer size can be greater than 4k, so it can cross page boundary.
    pub fn get_manifest_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmReqError> {
        let gpa = PhysAddr::from(self.manifest_gpa);
        let size =
            usize::try_from(self.manifest_size).map_err(|_| SvsmReqError::invalid_parameter())?;
        if !gpa.is_page_aligned() {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok(MemoryRegion::new(gpa, size))
    }

    /// Returns the report buffer gpa and size
    /// Checks if gpa is page aligned and valid.
    /// Report buffer size can be greater than 4k, so it can cross page boundary.
    pub fn get_report_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmReqError> {
        let gpa = PhysAddr::from(self.report_gpa);
        let size =
            usize::try_from(self.report_size).map_err(|_| SvsmReqError::invalid_parameter())?;
        if !gpa.is_page_aligned() {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok(MemoryRegion::new(gpa, size))
    }

    /// Returns an optional MemoryRegion describing the certificate buffer.
    ///
    /// Behaviour:
    /// - certificate_size == 0 -> Ok(None)
    ///   (caller did not request certificates / extended report)
    /// - 0 < certificate_size <= MAX_CERTIFICATE_SIZE and certificate_gpa page aligned
    ///   -> Ok(Some(MemoryRegion))
    /// - Otherwise -> Err(SvsmReqError::invalid_parameter())
    ///
    /// Notes:
    /// - Buffer may span multiple pages but must be physically contiguous.
    /// - Buffer GPA must be page aligned.
    /// - Size is capped at MAX_CERTIFICATE_SIZE (0x4000 bytes).
    pub fn get_certificate_region(&self) -> Result<Option<MemoryRegion<PhysAddr>>, SvsmReqError> {
        let size = usize::try_from(self.certificate_size)
            .map_err(|_| SvsmReqError::invalid_parameter())?;

        // If size is 0, the certificate buffer is not present.
        // This is valid and shall not return an error.
        // It is used to indicate that the user does not want an extended attestation
        // that returns certificates.
        if size == 0 {
            return Ok(None);
        }

        // Ensure that size is not greater than MAX_CERTIFICATE_SIZE
        if size > MAX_CERTIFICATE_SIZE {
            return Err(SvsmReqError::invalid_parameter());
        }

        let gpa = PhysAddr::from(self.certificate_gpa);
        if !gpa.is_page_aligned() {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok(Some(MemoryRegion::new(gpa, size)))
    }

    /// Returns true if an extended report is requested
    /// Extended report is requested by providing a certificate buffer gpa and
    /// providing a non-zero certificate buffer size.
    pub fn is_extended_report(&self) -> Result<bool, SvsmReqError> {
        // If certificate buffer size is greater than 0, it is an extended report.
        // else it is a regular report.
        let size = usize::try_from(self.certificate_size)
            .map_err(|_| SvsmReqError::invalid_parameter())?;
        Ok(size > 0)
    }
}

#[derive(Clone)]
struct GuidTableEntry {
    guid: uuid::Uuid,
    data: Vec<u8>,
}

struct GuidTable {
    entries: Vec<GuidTableEntry>,
}

impl GuidTable {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    // Only used when features are enabled.
    #[allow(dead_code)]
    fn push(&mut self, guid: uuid::Uuid, data: Vec<u8>) {
        self.entries.push(GuidTableEntry { guid, data })
    }

    fn header_size(&self) -> usize {
        // The services manifest header is 24 bytes, followed by 24 bytes for each entry.
        (1 + self.entries.len()) * GUID_HEADER_ENTRY_SIZE
    }

    /// Returns how many bytes the wire ABI representation takes.
    fn len(&self) -> usize {
        let init = self.header_size();
        self.entries
            .iter()
            .fold(init, |acc, entry| acc + entry.data.len())
    }

    // Writes the GuidTable contents at the end of `data` or returns an error.
    fn to_vec(&self) -> Result<Vec<u8>, SvsmError> {
        let length = self.len();
        let mut data: Vec<u8> = Vec::with_capacity(length);
        data.extend_from_slice(&SERVICES_MANIFEST_GUID.to_bytes_le());
        data.extend_from_slice(&(length as u32).to_le_bytes());
        data.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        let mut data_cursor = self.header_size() as u32;
        self.entries.iter().for_each(|entry| {
            data.extend_from_slice(&entry.guid.to_bytes_le());
            data.extend_from_slice(&data_cursor.to_le_bytes());
            data.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
            data_cursor += entry.data.len() as u32;
        });
        self.entries
            .iter()
            .for_each(|entry| data.extend_from_slice(entry.data.as_slice()));
        Ok(data)
    }
}

// Attest Single Service Operation structure, as defined in
// Table 13 of Secure VM Service Module for SEV-SNP Guests
// 58019 Rev. 1.00 July 2023
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
pub struct AttestSingleServiceOp {
    op: AttestServicesOp,
    guid: [u8; 16],
    manifest_ver: u32,
    reserved_5: [u8; 4],
}

impl AttestSingleServiceOp {
    /// Take a slice and return a reference for Self
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let ops: &Self =
            Self::ref_from_bytes(buffer).map_err(|_| SvsmReqError::invalid_parameter())?;
        if !ops.is_reserved_clear() || !ops.is_manifest_version_valid() {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok(ops)
    }

    /// Checks if reserved fields are all set to zero
    pub fn is_reserved_clear(&self) -> bool {
        self.op.is_reserved_clear() && self.reserved_5.iter().all(|&x| x == 0)
    }

    /// Returns the nonce
    pub fn get_nonce(&self) -> Result<Vec<u8>, SvsmReqError> {
        self.op.get_nonce()
    }

    /// Returns the manifest buffer gpa and size
    /// Checks if gpa is page aligned and valid.
    /// Manifest buffer size can be greater than 4k, so it can cross page boundary.
    pub fn get_manifest_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmReqError> {
        self.op.get_manifest_region()
    }

    /// Returns the report buffer gpa and size
    /// Checks if gpa is page aligned and valid.
    /// Report buffer size can be greater than 4k, so it can cross page boundary.
    pub fn get_report_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmReqError> {
        self.op.get_report_region()
    }

    pub fn get_manifest_version(&self) -> u32 {
        self.manifest_ver
    }

    fn is_manifest_version_valid(&self) -> bool {
        // Currently only manifest version 0 is supported
        self.manifest_ver == 0
    }

    /// Returns the guid
    pub fn get_guid(&self) -> uuid::Uuid {
        Uuid::from_bytes_le(self.guid)
    }

    /// See [`AttestServicesOp::get_certificate_region`] for details.
    pub fn get_certificate_region(&self) -> Result<Option<MemoryRegion<PhysAddr>>, SvsmReqError> {
        self.op.get_certificate_region()
    }

    /// See [`AttestServicesOp::is_extended_report`] for details.
    pub fn is_extended_report(&self) -> Result<bool, SvsmReqError> {
        self.op.is_extended_report()
    }
}

fn get_attestation_report_standard(nonce: &[u8]) -> Result<Box<SnpReportResponse>, SvsmReqError> {
    let mut resp = SnpReportResponse::new_box_zeroed()
        .map_err(|_| SvsmReqError::FatalError(SvsmError::Mem))?;
    let resp_buffer = resp.as_mut_bytes();
    // Cast error is infallibly discarded.
    let (report_req, _) = SnpReportRequest::mut_from_prefix(resp_buffer)
        .map_err(|_| SvsmReqError::invalid_parameter())?;
    // Zero initialized, so
    // vmpl=0
    // flags=0: Use VLEK if installed, otherwise VCEK.
    report_req.user_data = nonce
        .try_into()
        .map_err(|_| SvsmReqError::invalid_parameter())?;
    let _response_size = get_regular_report(resp_buffer)?;

    Ok(resp)
}

fn get_attestation_report_extended(
    nonce: &[u8],
) -> Result<(Box<SnpReportResponse>, Box<[u8; MAX_CERTIFICATE_SIZE]>), SvsmReqError> {
    let mut resp = SnpReportResponse::new_box_zeroed()
        .map_err(|_| SvsmReqError::FatalError(SvsmError::Mem))?;
    let resp_buffer = resp.as_mut_bytes();
    // Cast error is infallibly discarded.
    let (report_req, _) = SnpReportRequest::mut_from_prefix(resp_buffer)
        .map_err(|_| SvsmReqError::invalid_parameter())?;

    // Extended report requires a certificate buffer.
    // Allocate a zero initialized buffer for certificates.
    // MAX_CERTIFICATE_SIZE is defined as 0x4000 bytes (16k).
    let mut certs = <[u8; MAX_CERTIFICATE_SIZE]>::new_box_zeroed()
        .map_err(|_| SvsmReqError::FatalError(SvsmError::Mem))?;
    let certs_buffer = certs.as_mut_bytes();

    // Zero initialized, so
    // vmpl=0
    // flags=0: Use VLEK if installed, otherwise VCEK.
    report_req.user_data = nonce
        .try_into()
        .map_err(|_| SvsmReqError::invalid_parameter())?;

    let _response_size = get_extended_report(resp_buffer, certs_buffer)?;

    Ok((resp, certs))
}

fn write_report_and_manifest(
    manifest: &[u8],
    params: &mut RequestParams,
    ops: &AttestServicesOp,
    report: &[u8],
) -> Result<(), SvsmReqError> {
    // Get attestation report buffer's gPA from call's Attest Services Operation structure.
    // The buffer is required to be page aligned but can be bigger than 4K so can cross pages.
    // If it is bigger than 4K, it must be physically contiguous.
    let report_region = ops.get_report_region()?;

    // Get manifest buffer's GPA from call's Attest Services Operation structure
    // The buffer is required to be page aligned but can be bigger than 4K so can cross pages.
    // If it is bigger than 4K, it must be physically contiguous.
    let manifest_region = ops.get_manifest_region()?;

    // Check that the manifest will fit in the buffer by checking that the length of the manifest
    // is less than the size of the buffer. The size of the buffer was used to create the guard,
    // so can not be tricked into writing outside the buffer.
    // If the manifest is larger than the buffer, it is either a malformed manifest or buffer too
    // small. In either case, return an error.
    if manifest.len() > manifest_region.len() {
        return Err(SvsmError::Attestation(AttestError::Manifest).into());
    }

    // Check that the attestation report will fit in the buffer by checking that the length of the
    // report is less than the size of the buffer. The size of the buffer was used to create the
    // guard, so can not be tricked into writing outside the buffer.
    // If the report is larger than the buffer, it is either a malformed report or buffer too small.
    // In either case, return an error.
    if report.len() > report_region.len() {
        return Err(SvsmError::Attestation(AttestError::Report).into());
    }

    copy_slice_to_guest(report, report_region.start())?;

    // Set report size in bytes in r8 register
    params.r8 = report
        .len()
        .try_into()
        .map_err(|_| SvsmError::Attestation(AttestError::Report))?;

    copy_slice_to_guest(manifest, manifest_region.start())?;

    // Set the manifest size in bytes in rcx register
    params.rcx = manifest
        .len()
        .try_into()
        .map_err(|_| SvsmError::Attestation(AttestError::Manifest))?;

    Ok(())
}

fn write_certs(
    certs: &[u8],
    params: &mut RequestParams,
    ops: &AttestServicesOp,
) -> Result<(), SvsmReqError> {
    // Get certificate buffer's gPA from call's Attest Services Operation structure.
    // The buffer is required to be page aligned but can be bigger than 4K so can cross pages.
    // If it is bigger than 4K, it must be physically contiguous.
    let cert_region = ops.get_certificate_region()?;

    // If certificate region is None, it means that the certificate buffer is not present.
    // This is valid and shall not return an error.
    let cert_region = match cert_region {
        Some(region) => region,
        None => {
            // If the certificate region is None, it means that the certificate buffer is not present.
            // This is valid and shall not return an error.
            // It is used to indicate that the user does not want an extended attestation
            // that returns certificates.
            // Set certificate size to 0, so that the caller knows that there is no certificate.
            params.rdx = 0;
            return Ok(());
        }
    };

    // According to "SEV-ES Guest-Hypervisor Communication Block Standardization, Revision 2.04"
    // the initial 24 bytes of the certificate buffer is the certificate header and will be all zeros
    // if there is no certificate returned.
    // This is valid and shall not return an error.
    // Set certificate size to 0, so that the caller knows that there is no certificate.
    if certs[..24] == [0; 24] {
        params.rdx = 0;
        return Ok(());
    }

    // Check that certificates fit in the buffer. If too large,
    // return an error indicating the buffer is too small .
    if certs.len() > cert_region.len() {
        return Err(SvsmError::Attestation(AttestError::CertificateSize).into());
    }

    copy_slice_to_guest(certs, cert_region.start())?;

    // Set certificate size in bytes in rdx register
    params.rdx = certs
        .len()
        .try_into()
        .map_err(|_| SvsmError::Attestation(AttestError::Certificate))?;

    Ok(())
}

fn get_attestation_report(
    hash: &[u8],
    manifest: &[u8],
    params: &mut RequestParams,
    ops: &AttestServicesOp,
) -> Result<(), SvsmReqError> {
    if ops.is_extended_report()? {
        // If the report is an extended report, it means that the caller requested a certificate.
        // Get extended attestation report from PSP with Sha512(nonce||manifest) as REPORT_DATA.
        // Handle SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(certs_buffer_size,psp_rc,)))
        // from the PSP indicating that the certificate buffer is too small.
        // The required size (in 4 KB pages) is in certs_buffer_size.
        // Per SVSM spec, return required size (in bytes) in rdx register and raise an error.
        let (resp, certs) = match get_attestation_report_extended(hash) {
            Ok((resp, certs)) => (resp, certs),
            Err(SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(
                certs_buffer_size,
                _psp_rc,
            )))) => {
                // The PSP returned an error code indicating that the buffer size is too small.
                // The required size is in certs_buffer_size but specified as number of 4 KB pages.
                // Per SVSM spec, return required size (in bytes) in rdx and raise an error
                params.rdx = certs_buffer_size << PAGE_SHIFT;
                return Err(SvsmError::Attestation(AttestError::CertificateSize).into());
            }
            Err(e) => return Err(e),
        };

        write_report_and_manifest(manifest, params, ops, resp.report.as_bytes())?;
        write_certs(certs.as_slice(), params, ops)
    } else {
        // Get attestation standard report from PSP with Sha512(nonce||manifest) as REPORT_DATA.
        let resp = get_attestation_report_standard(hash)?;

        write_report_and_manifest(manifest, params, ops, resp.report.as_bytes())
    }
}

#[allow(dead_code)]
fn attest_single_service(
    manifest: &[u8],
    params: &mut RequestParams,
    ops: &AttestSingleServiceOp,
) -> Result<(), SvsmReqError> {
    let nonce = ops.get_nonce()?;

    // Concatenate nonce and manifest and hash per page 29 of
    // "Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00".
    let nonce_and_manifest = [&nonce[..], manifest].concat();
    let hash = Sha512::digest(&nonce_and_manifest);

    get_attestation_report(hash.as_slice(), manifest, params, &ops.op)
}

#[cfg(all(feature = "vtpm", not(test)))]
fn attest_single_vtpm(
    params: &mut RequestParams,
    ops: &AttestSingleServiceOp,
) -> Result<(), SvsmReqError> {
    attest_single_service(vtpm_get_manifest()?.as_slice(), params, ops)
}

fn attest_multiple_services(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa = PhysAddr::from(params.rcx);

    let attest_op =
        read_from_guest::<AttestServicesOp>(gpa).map_err(|_| SvsmReqError::invalid_parameter())?;

    // Attest multiple services is expected to return a GUID table (mixed endian ordering) of the
    // enumerated active services' attestation manifest. A service that does not have its own
    // manifest is still enumerated, but with an empty data blob.
    #[allow(unused_mut)]
    let mut services = GuidTable::new();

    #[cfg(all(feature = "vtpm", not(test)))]
    services.push(SVSM_ATTEST_VTPM_GUID, vtpm_get_manifest()?);
    let manifest = services.to_vec()?;
    let mut nonce_and_manifest = attest_op.get_nonce()?;
    nonce_and_manifest.extend_from_slice(manifest.as_slice());

    // Concatenate nonce and manifest and hash per page 29 of
    // "Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00".
    let hash = Sha512::digest(&nonce_and_manifest);

    // Get attestation report from PSP with Sha512(nonce||manifest) as REPORT_DATA.
    get_attestation_report(hash.as_slice(), manifest.as_slice(), params, &attest_op)
}

#[allow(clippy::needless_pass_by_ref_mut)]
fn attest_single_service_handler(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // Get the gpa of Attest Single Service Operation structure
    let gpa = PhysAddr::from(params.rcx);

    let attest_op = read_from_guest::<AttestSingleServiceOp>(gpa)
        .map_err(|_| SvsmReqError::invalid_parameter())?;

    // Extract the GUID from the Attest Single Service Operation structure.
    // The GUID is used to determine the specific service to be attested.
    // Currently, only the VTPM service with the GUID 0xebf176c4_2301a545_9641b4e7_dde5bfe3
    // is supported, see 8.3.1 of the spec "Secure VM Service Module for SEV-SNP Guests
    // 58019 Rev. 1.00" for more details.
    match attest_op.get_guid() {
        #[cfg(all(feature = "vtpm", not(test)))]
        SVSM_ATTEST_VTPM_GUID => attest_single_vtpm(params, &attest_op),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

pub fn attest_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_ATTEST_SERVICES => attest_multiple_services(params),
        SVSM_ATTEST_SINGLE_SERVICE => attest_single_service_handler(params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::errors::SvsmResultCode;
    use alloc::vec;
    use core::mem::{offset_of, size_of};
    use zerocopy::FromZeros;

    fn is_invalid_parameter(err: &SvsmReqError) -> bool {
        matches!(
            err,
            SvsmReqError::RequestError(SvsmResultCode::INVALID_PARAMETER)
        )
    }

    fn is_unsupported_protocol(err: &SvsmReqError) -> bool {
        matches!(
            err,
            SvsmReqError::RequestError(SvsmResultCode::UNSUPPORTED_PROTOCOL)
        )
    }

    mod attest_services {
        use super::*;

        fn base_op() -> AttestServicesOp {
            AttestServicesOp::new_zeroed()
        }

        #[test]
        fn op_layout() {
            assert_eq!(offset_of!(AttestServicesOp, report_gpa), 0x00);
            assert_eq!(offset_of!(AttestServicesOp, report_size), 0x08);
            assert_eq!(offset_of!(AttestServicesOp, reserved_1), 0x0c);
            assert_eq!(offset_of!(AttestServicesOp, nonce_gpa), 0x10);
            assert_eq!(offset_of!(AttestServicesOp, nonce_size), 0x18);
            assert_eq!(offset_of!(AttestServicesOp, reserved_2), 0x1a);
            assert_eq!(offset_of!(AttestServicesOp, manifest_gpa), 0x20);
            assert_eq!(offset_of!(AttestServicesOp, manifest_size), 0x28);
            assert_eq!(offset_of!(AttestServicesOp, reserved_3), 0x2c);
            assert_eq!(offset_of!(AttestServicesOp, certificate_gpa), 0x30);
            assert_eq!(offset_of!(AttestServicesOp, certificate_size), 0x38);
            assert_eq!(offset_of!(AttestServicesOp, reserved_4), 0x3c);
            assert_eq!(size_of::<AttestServicesOp>(), 0x40);
        }

        #[test]
        fn reserved_clear_valid() {
            let op = base_op();
            assert!(op.is_reserved_clear());
        }

        #[test]
        fn reserved_clear_invalid() {
            for offset in [
                offset_of!(AttestServicesOp, reserved_1),
                offset_of!(AttestServicesOp, reserved_2),
                offset_of!(AttestServicesOp, reserved_3),
                offset_of!(AttestServicesOp, reserved_4),
            ] {
                let mut bytes = base_op().as_bytes().to_vec();
                bytes[offset] = 0xff;
                let op = AttestServicesOp::ref_from_bytes(&bytes).unwrap();
                assert!(
                    !op.is_reserved_clear(),
                    "reserved check should fail for byte at offset {offset:#x}"
                );
            }
        }

        #[test]
        fn try_from_as_ref_valid() {
            let op = base_op();
            let bytes = op.as_bytes();
            assert!(AttestServicesOp::try_from_as_ref(bytes).is_ok());
        }

        #[test]
        fn try_from_as_ref_short_buffer() {
            let op = base_op();
            let bytes = op.as_bytes();
            let err = AttestServicesOp::try_from_as_ref(&bytes[..bytes.len() - 1]).unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn try_from_as_ref_nonzero_reserved() {
            for offset in [
                offset_of!(AttestServicesOp, reserved_1),
                offset_of!(AttestServicesOp, reserved_2),
                offset_of!(AttestServicesOp, reserved_3),
                offset_of!(AttestServicesOp, reserved_4),
            ] {
                let mut bytes = base_op().as_bytes().to_vec();
                bytes[offset] = 1;
                let err = AttestServicesOp::try_from_as_ref(&bytes).unwrap_err();
                assert!(
                    is_invalid_parameter(&err),
                    "should reject nonzero reserved at offset {offset:#x}"
                );
            }
        }

        #[test]
        fn get_report_region_aligned() {
            let mut op = base_op();
            op.report_gpa = 0x1000;
            op.report_size = 0x2000;
            let region = op.get_report_region().unwrap();
            assert_eq!(region.start(), PhysAddr::from(0x1000u64));
            assert_eq!(region.len(), 0x2000);
        }

        #[test]
        fn get_report_region_unaligned() {
            let mut op = base_op();
            op.report_gpa = 0x1001;
            op.report_size = 0x1000;
            let err = op.get_report_region().unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn get_manifest_region_aligned() {
            let mut op = base_op();
            op.manifest_gpa = 0x2000;
            op.manifest_size = 0x1000;
            let region = op.get_manifest_region().unwrap();
            assert_eq!(region.start(), PhysAddr::from(0x2000u64));
            assert_eq!(region.len(), 0x1000);
        }

        #[test]
        fn get_manifest_region_unaligned() {
            let mut op = base_op();
            op.manifest_gpa = 0x2001;
            op.manifest_size = 0x1000;
            let err = op.get_manifest_region().unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn get_certificate_region_none_when_size_zero() {
            let op = base_op();
            assert!(op.get_certificate_region().unwrap().is_none());
        }

        #[test]
        fn get_certificate_region_some_when_valid() {
            let mut op = base_op();
            op.certificate_gpa = 0x4000;
            op.certificate_size = 0x1000;
            let region = op.get_certificate_region().unwrap().unwrap();
            assert_eq!(region.start(), PhysAddr::from(0x4000u64));
            assert_eq!(region.len(), 0x1000);
        }

        #[test]
        fn get_certificate_region_accepts_max_size() {
            let mut op = base_op();
            op.certificate_gpa = 0x4000;
            op.certificate_size = MAX_CERTIFICATE_SIZE as u32;
            assert!(op.get_certificate_region().unwrap().is_some());
        }

        #[test]
        fn get_certificate_region_rejects_oversize() {
            let mut op = base_op();
            op.certificate_gpa = 0x4000;
            op.certificate_size = (MAX_CERTIFICATE_SIZE + 1) as u32;
            let err = op.get_certificate_region().unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn get_certificate_region_rejects_unaligned() {
            let mut op = base_op();
            op.certificate_gpa = 0x4001;
            op.certificate_size = 0x1000;
            let err = op.get_certificate_region().unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn is_extended_report() {
            let mut op = base_op();
            assert!(!op.is_extended_report().unwrap());

            op.certificate_size = 0x1000;
            assert!(op.is_extended_report().unwrap());
        }
    }

    mod attest_single_service {
        use super::*;

        fn base_op() -> AttestSingleServiceOp {
            AttestSingleServiceOp::new_zeroed()
        }

        #[test]
        fn op_layout() {
            assert_eq!(offset_of!(AttestSingleServiceOp, op), 0x00);
            assert_eq!(offset_of!(AttestSingleServiceOp, guid), 0x40);
            assert_eq!(offset_of!(AttestSingleServiceOp, manifest_ver), 0x50);
            assert_eq!(offset_of!(AttestSingleServiceOp, reserved_5), 0x54);
            assert_eq!(size_of::<AttestSingleServiceOp>(), 0x58);
        }

        #[test]
        fn reserved_clear_valid() {
            let op = base_op();
            assert!(op.is_reserved_clear());
        }

        #[test]
        fn reserved_clear_invalid_reserved_5() {
            let mut bytes = base_op().as_bytes().to_vec();
            bytes[offset_of!(AttestSingleServiceOp, reserved_5)] = 0xff;
            let op = AttestSingleServiceOp::ref_from_bytes(&bytes).unwrap();
            assert!(!op.is_reserved_clear());
        }

        #[test]
        fn reserved_clear_invalid_inner() {
            let mut bytes = base_op().as_bytes().to_vec();
            bytes[offset_of!(AttestServicesOp, reserved_1)] = 0xff;
            let op = AttestSingleServiceOp::ref_from_bytes(&bytes).unwrap();
            assert!(!op.is_reserved_clear());
        }

        #[test]
        fn try_from_as_ref_valid() {
            let op = base_op();
            let bytes = op.as_bytes();
            assert!(AttestSingleServiceOp::try_from_as_ref(bytes).is_ok());
        }

        #[test]
        fn try_from_as_ref_rejects_manifest_version() {
            let mut bytes = base_op().as_bytes().to_vec();
            bytes[offset_of!(AttestSingleServiceOp, manifest_ver)] = 1;
            let err = AttestSingleServiceOp::try_from_as_ref(&bytes).unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn try_from_as_ref_rejects_reserved_5() {
            let mut bytes = base_op().as_bytes().to_vec();
            bytes[offset_of!(AttestSingleServiceOp, reserved_5)] = 1;
            let err = AttestSingleServiceOp::try_from_as_ref(&bytes).unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn try_from_as_ref_rejects_inner_reserved() {
            let mut bytes = base_op().as_bytes().to_vec();
            bytes[offset_of!(AttestServicesOp, reserved_1)] = 1;
            let err = AttestSingleServiceOp::try_from_as_ref(&bytes).unwrap_err();
            assert!(is_invalid_parameter(&err));
        }

        #[test]
        fn get_guid_round_trip() {
            let expected = uuid!("c476f1eb-0123-45a5-9641-b4e7dde5bfe3");
            let mut op = base_op();
            op.guid = expected.to_bytes_le();
            assert_eq!(op.get_guid(), expected);
        }

        #[test]
        fn manifest_version_validation() {
            let op = base_op();
            assert!(op.is_manifest_version_valid());

            let mut bytes = op.as_bytes().to_vec();
            bytes[offset_of!(AttestSingleServiceOp, manifest_ver)] = 1;
            let op2 = AttestSingleServiceOp::ref_from_bytes(&bytes).unwrap();
            assert!(!op2.is_manifest_version_valid());
        }

        #[test]
        fn is_extended_report() {
            let mut op = base_op();
            assert!(!op.op.is_extended_report().unwrap());

            op.op.certificate_size = 0x1000;
            assert!(op.op.is_extended_report().unwrap());
        }
    }

    mod guid_table {
        use super::*;

        #[test]
        fn empty() {
            let table = GuidTable::new();
            assert_eq!(table.header_size(), GUID_HEADER_ENTRY_SIZE);
            assert_eq!(table.len(), GUID_HEADER_ENTRY_SIZE);

            let data = table.to_vec().unwrap();
            assert_eq!(data.len(), GUID_HEADER_ENTRY_SIZE);

            assert_eq!(&data[..16], &SERVICES_MANIFEST_GUID.to_bytes_le());
            let total_len = u32::from_le_bytes(data[16..20].try_into().unwrap());
            assert_eq!(total_len as usize, GUID_HEADER_ENTRY_SIZE);
            let entry_count = u32::from_le_bytes(data[20..24].try_into().unwrap());
            assert_eq!(entry_count, 0);
        }

        #[test]
        fn single_entry() {
            let guid = uuid!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            let payload = vec![0x01, 0x02, 0x03, 0x04];

            let mut table = GuidTable::new();
            table.push(guid, payload.clone());

            assert_eq!(table.header_size(), 48);
            assert_eq!(table.len(), 48 + payload.len());

            let data = table.to_vec().unwrap();
            assert_eq!(data.len(), 48 + payload.len());

            let entry_count = u32::from_le_bytes(data[20..24].try_into().unwrap());
            assert_eq!(entry_count, 1);

            assert_eq!(&data[24..40], &guid.to_bytes_le());
            let entry_offset = u32::from_le_bytes(data[40..44].try_into().unwrap());
            assert_eq!(entry_offset, 48);
            let entry_size = u32::from_le_bytes(data[44..48].try_into().unwrap());
            assert_eq!(entry_size as usize, payload.len());

            assert_eq!(&data[48..], &payload);
        }

        #[test]
        fn multiple_entries() {
            let guid1 = uuid!("11111111-1111-1111-1111-111111111111");
            let guid2 = uuid!("22222222-2222-2222-2222-222222222222");
            let payload1 = vec![0xaa; 10];
            let payload2 = vec![0xbb; 20];

            let mut table = GuidTable::new();
            table.push(guid1, payload1.clone());
            table.push(guid2, payload2.clone());

            assert_eq!(table.header_size(), 72);
            assert_eq!(table.len(), 72 + 10 + 20);

            let data = table.to_vec().unwrap();
            assert_eq!(data.len(), 72 + 30);

            let entry_count = u32::from_le_bytes(data[20..24].try_into().unwrap());
            assert_eq!(entry_count, 2);

            let offset1 = u32::from_le_bytes(data[40..44].try_into().unwrap());
            assert_eq!(offset1, 72);

            let offset2 = u32::from_le_bytes(data[64..68].try_into().unwrap());
            assert_eq!(offset2, 82);

            assert_eq!(&data[72..82], &payload1);
            assert_eq!(&data[82..102], &payload2);
        }
    }

    mod protocol_routing {
        use super::*;

        #[test]
        fn rejects_unknown_request() {
            let mut params = RequestParams::default();
            let err = attest_protocol_request(99, &mut params).unwrap_err();
            assert!(is_unsupported_protocol(&err));
        }
    }
}
