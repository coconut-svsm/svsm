// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024  Hewlett Packard Enterprise Development LP
//
// Author: Geoffrey Ndu (gtn@hpe.com)

//! Attestation protocol implementation

extern crate alloc;

use crate::protocols::{errors::SvsmReqError, RequestParams};
use crate::{
    address::{Address, PhysAddr},
    mm::{valid_phys_address, PerCPUPageMappingGuard},
};
#[cfg(all(feature = "vtpm", not(test)))]
use crate::{
    greq::{
        pld_report::{SnpReportResponse, USER_DATA_SIZE},
        services::get_regular_report,
    },
    vtpm::vtpm_get_manifest,
};
use alloc::vec::Vec;
#[cfg(all(feature = "vtpm", not(test)))]
use core::slice::from_raw_parts_mut;
use core::{mem::size_of, slice::from_raw_parts};
#[cfg(all(feature = "vtpm", not(test)))]
use sha2::{Digest, Sha512};
const SVSM_ATTEST_SERVICES: u32 = 0;
const SVSM_ATTEST_SINGLE_SERVICE: u32 = 1;
const ATTEST_SINGLE_SERVICE_OP_SIZE: usize = size_of::<AttestSingleServiceOp>();

#[cfg(all(feature = "vtpm", not(test)))]
const SVSM_ATTEST_VTPM_GUID: u128 = u128::from_le_bytes([
    0xeb, 0xf1, 0x76, 0xc4, 0x23, 0x01, 0xa5, 0x45, 0x96, 0x41, 0xb4, 0xe7, 0xdd, 0xe5, 0xbf, 0xe3,
]);

// Attest Single Service Operation structure, as defined in
// Table 13 of Secure VM Service Module for SEV-SNP Guests
// 58019 Rev. 1.00 July 2023
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct AttestSingleServiceOp {
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
    guid: [u8; 16],
    manifest_ver: u32,
    reserved_5: [u8; 4],
}

impl AttestSingleServiceOp {
    /// Take a slice and return a reference for Self
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let buffer = buffer
            .get(..size_of::<Self>())
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // SAFETY: AttestSingleServiceOp has no invalid representations, as it is
        // comprised entirely of integer types. It is repr(packed), so its
        // required alignment is simply 1. We have checked the size, so this
        // is entirely safe.
        let ops = unsafe { &*buffer.as_ptr().cast::<Self>() };

        if !ops.is_reserved_clear() || !ops.is_manifest_version_valid() {
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
            && self.reserved_5.iter().all(|&x| x == 0)
    }

    /// Returns the nonce
    pub fn get_nonce(&self) -> Result<Vec<u8>, SvsmReqError> {
        let (gpa, size) = self.get_nonce_gpa_and_size()?;

        // Check that the nonce size is not greater than 64 bytes.
        // Nonce size is 64 bytes per Table 21 of
        // "SEV Secure Nested Paging Firmware ABI Specification, Revision 1.56"
        if size > 64 {
            return Err(SvsmReqError::invalid_parameter());
        }

        // get_nonce_gpa_and_size() already validated that gpa is valid and does not cross page
        // boundary. So we can safely map in the nonce.
        let start = gpa.page_align();
        let offset = gpa.page_offset();

        let guard = PerCPUPageMappingGuard::create_4k(start)?;
        let vaddr = guard.virt_addr() + offset;

        // SAFETY: vaddr points to a new mapped page region. And get_nonce_gpa_and_size() already
        // validated that gpa is valid  and that the size of the nonce won't make us cross page
        // boundaries.
        // So we can safely read the nonce.
        let buffer = unsafe { from_raw_parts(vaddr.as_mut_ptr::<u8>(), size) };
        let nonce = buffer.to_vec();

        Ok(nonce)
    }

    /// Returns the nonce buffer gpa and size
    /// Checks if gpa is valid and does not cross page boundary.
    /// Nonce not required to be page aligned.
    pub fn get_nonce_gpa_and_size(&self) -> Result<(PhysAddr, usize), SvsmReqError> {
        let gpa = PhysAddr::from(self.nonce_gpa);
        // Won't fail on amd64 as usize > u16 always
        let size = self.nonce_size.into();
        if !valid_phys_address(gpa) || gpa.crosses_page(size) {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok((gpa, size))
    }

    /// Returns the manifest buffer gpa and size
    /// Checks if gpa is page aligned and valid.
    /// Manifest buffer size can be greater than 4k, so it can cross page boundary.
    pub fn get_manifest_gpa_and_size(&self) -> Result<(PhysAddr, usize), SvsmReqError> {
        let gpa = PhysAddr::from(self.manifest_gpa);
        // Won't fail on amd64 as usize > u32 always
        // TODO return protocol specific error code
        let size =
            usize::try_from(self.manifest_size).map_err(|_| SvsmReqError::invalid_parameter())?;
        if !gpa.is_page_aligned() || !valid_phys_address(gpa) {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok((gpa, size))
    }

    /// Returns the report buffer gpa and size
    /// Checks if gpa is page aligned and valid.
    /// Report buffer size can be greater than 4k, so it can cross page boundary.
    pub fn get_report_gpa_and_size(&self) -> Result<(PhysAddr, usize), SvsmReqError> {
        let gpa = PhysAddr::from(self.report_gpa);
        // Won't fail on amd64 as usize > u32 always
        // TODO return protocol specific error code
        let size =
            usize::try_from(self.report_size).map_err(|_| SvsmReqError::invalid_parameter())?;
        if !gpa.is_page_aligned() || !valid_phys_address(gpa) {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok((gpa, size))
    }

    pub fn get_manifest_version(&self) -> u32 {
        self.manifest_ver
    }

    fn is_manifest_version_valid(&self) -> bool {
        // Currently only manifest version 0 is supported
        self.manifest_ver == 0
    }

    /// Returns the guid
    pub fn get_guid(&self) -> u128 {
        u128::from_le_bytes(self.guid)
    }
}

#[cfg(all(feature = "vtpm", not(test)))]
fn get_attestation_report(nonce: &[u8]) -> Result<Vec<u8>, SvsmReqError> {
    // Construct attestation request message to send to SNP
    let mut report_req = Vec::<u8>::with_capacity(size_of::<SnpReportResponse>());
    let mut buf = Vec::<u8>::with_capacity(USER_DATA_SIZE);
    if nonce.len() > USER_DATA_SIZE {
        // If the nonce is greater than the user data size, return an error as something is wrong.
        return Err(SvsmReqError::invalid_parameter());
    }
    // Copy user attestation request nonce to buffer
    buf.extend_from_slice(nonce);
    report_req.extend_from_slice(&buf[..nonce.len()]);

    // Set request VMPL to 0
    report_req.extend_from_slice(&0_u32.to_le_bytes());

    // Set reserved bytes to zeros
    report_req.extend_from_slice(&[0; 28]);

    // Make sure buffer is big enough to hold the report
    report_req.resize(size_of::<SnpReportResponse>(), 0);

    // Send request to snp
    let _response_size = get_regular_report(report_req.as_mut_slice())?;

    // Per Table 24 of "SEV Secure Nested Paging Firmware ABI Specification, Revision 1.56",
    // attestation report starts at byte offset 0x20. And get_regular_report() already called
    // SnpReportResponse::validate_report() which checks that the report is the right length.
    // So we can always drain the first 0x20 bytes without panicking at runtime.
    report_req.drain(0..0x20);

    Ok(report_req)
}

#[cfg(all(feature = "vtpm", not(test)))]
fn attest_single_vtpm(
    params: &mut RequestParams,
    ops: &AttestSingleServiceOp,
) -> Result<(), SvsmReqError> {
    let nonce = ops.get_nonce()?;

    // Get the cached EKpub from the VTPM. Returns an error if the EKpub is not cached.
    let manifest = vtpm_get_manifest()?;

    // Concatenate nonce and manifest and hash per page 29 of
    // "Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00".
    let nonce_and_manifest = [&nonce[..], &manifest[..]].concat();
    let hash = Sha512::digest(&nonce_and_manifest);

    // Get attestation report from PSP with Sha512(nonce||manifest) as REPORT_DATA.
    let report = get_attestation_report(hash.as_slice())?;

    // Get attestation report buffer's gPA from call's Attest Single Service Operation structure.
    // The buffer is required to be page aligned but can be bigger than 4K so can cross pages.
    // If it is bigger than 4K, it must be physically contiguous.
    let (report_gpa, report_size) = ops.get_report_gpa_and_size()?;
    let report_start = report_gpa.page_align();
    let report_offset = report_gpa.page_offset();
    let report_end = (report_start + report_size).page_align_up();

    let report_guard = PerCPUPageMappingGuard::create(report_start, report_end, 0)?;
    let report_vaddr = report_guard.virt_addr() + report_offset;

    // Check that the attestation report will fit in the buffer by checking that the length of the
    // report is less than the size of the buffer. The size of the buffer was used to create the
    // guard, so can not be tricked into writing outside the buffer.
    // If the report is larger than the buffer, it is either a malformed report or buffer too small.
    // In either case, return an error.
    if report.len() > report_size {
        log::error!("Malformed VTPM service attestation report");
        // TODO: Return a more protocol specific error code
        return Err(SvsmReqError::unsupported_protocol());
    }

    // SAFETY: Writing to guest_report_buffer via report_vaddr is safe due to the following checks:
    // 1. report_vaddr is a newly mapped region based on report_gpa
    // 2. report_gpa is mapped only after get_report_gpa_and_size() validates that it is
    //    guest-owned and page-aligned
    // 3. report_vaddr + report_size is fully within valid memory region created with
    //    PerCPUPageMappingGuard::create()
    // 4. report.len() is checked to be within report_size, preventing out-of-bounds writes.
    //
    // These validations collectively guarantee safe writes to the buffer.
    let guest_report_buffer =
        unsafe { from_raw_parts_mut(report_vaddr.as_mut_ptr::<u8>(), report_size) };
    guest_report_buffer[..report.len()].copy_from_slice(&report);

    // Set report size in bytes in r8 register
    // TODO use try_from or try_into to converts usize to u32
    params.r8 = report.len() as u64;

    // Get manifest buffer's GPA from call's Attest Single Service Operation structure
    // The buffer is required to be page aligned but can be bigger than 4K so can cross pages.
    // If it is bigger than 4K, it must be physically contiguous.
    let (manifest_gpa, manifest_size) = ops.get_manifest_gpa_and_size()?;
    let manifest_start = manifest_gpa.page_align();
    let manifest_offset = manifest_gpa.page_offset();
    let manifest_end = (manifest_start + manifest_size).page_align_up();

    let manifest_guard = PerCPUPageMappingGuard::create(manifest_start, manifest_end, 0)?;
    let manifest_vaddr = manifest_guard.virt_addr() + manifest_offset;

    // Check that the manifest will fit in the buffer by checking that the length of the manifest
    // is less than the size of the buffer. The size of the buffer was used to create the guard,
    // so can not be tricked into writing outside the buffer.
    // If the manifest is larger than the buffer, it is either a malformed manifest or buffer too
    // small. In either case, return an error.
    if manifest.len() > manifest_size {
        log::error!("Malformed VTPM service attestation manifest");
        // TODO: Return a more protocol specific error code
        return Err(SvsmReqError::unsupported_protocol());
    }

    // SAFETY: Writing to guest_manifest_buffer via manifest_vaddr is safe due to the following checks:
    // 1. manifest_vaddr is a newly mapped region based on manifest_gpa
    // 2. manifest_gpa is mapped only after get_manifest_gpa_and_size() validates that it is
    //    guest-owned and page-aligned
    // 3. manifest_vaddr + manifest_size is fully within valid memory region created with
    //    PerCPUPageMappingGuard::create()
    // 4. manifest.len() is checked to be within manifest_size, preventing out-of-bounds writes.
    let guest_manifest_buffer =
        unsafe { from_raw_parts_mut(manifest_vaddr.as_mut_ptr::<u8>(), manifest_size) };
    guest_manifest_buffer[..manifest.len()].copy_from_slice(&manifest);

    // Set the manifest size in bytes in rcx register
    // TODO use try_from or try_into to converts usize to u32
    params.rcx = manifest.len() as u64;

    // Does not support certificate currently, so setting certificate size to 0
    params.rdx = 0;

    Ok(())
}

fn attest_multiple_services(_params: &RequestParams) -> Result<(), SvsmReqError> {
    Err(SvsmReqError::unsupported_protocol())
}

#[allow(clippy::needless_pass_by_ref_mut)]
fn attest_single_service_handler(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // Get the gpa of Attest Single Service Operation structure
    let gpa = PhysAddr::from(params.rcx);

    if !valid_phys_address(gpa) || gpa.crosses_page(ATTEST_SINGLE_SERVICE_OP_SIZE) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let start = gpa.page_align();
    let offset = gpa.page_offset();
    let end = (gpa + ATTEST_SINGLE_SERVICE_OP_SIZE).page_align_up();

    // Map the Attest Single Service Operation structure table into a page
    // Per Table 13 of the spec "Secure VM Service Module for SEV-SNP Guests
    // 58019 Rev. 1.00", we only need  0x58 bytes.
    // The structure is not required to be page aligned.
    let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
    let vaddr = guard.virt_addr() + offset;

    // SAFETY: The untrusted gpa from the guest is validated above as a valid address.
    // The guard ensures that the page is newly mapped and not controlled by the guest.
    // We only use a portion of the page, less than the full page size.
    let buffer =
        unsafe { from_raw_parts(vaddr.as_ptr::<u8>(), size_of::<AttestSingleServiceOp>()) };
    let attest_op = AttestSingleServiceOp::try_from_as_ref(buffer)?;

    // Extract the GUID from the Attest Single Service Operation structure.
    // The GUID is used to determine the specific service to be attested.
    // Currently, only the VTPM service with the GUID 0xebf176c4_2301a545_9641b4e7_dde5bfe3
    // is supported, see 8.3.1 of the spec "Secure VM Service Module for SEV-SNP Guests
    // 58019 Rev. 1.00" for more details.
    let guid = attest_op.get_guid();

    match guid {
        #[cfg(all(feature = "vtpm", not(test)))]
        SVSM_ATTEST_VTPM_GUID => attest_single_vtpm(params, attest_op),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

pub fn attestation_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_ATTEST_SERVICES => attest_multiple_services(params),
        SVSM_ATTEST_SINGLE_SERVICE => attest_single_service_handler(params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}
