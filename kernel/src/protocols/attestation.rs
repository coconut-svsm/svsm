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
    types::PAGE_SIZE,
};
#[cfg(all(feature = "vtpm", not(test)))]
use crate::{
    greq::{
        pld_report::{SnpReportResponse, USER_DATA_SIZE},
        services::get_regular_report,
    },
    vtpm::vtpm_get_ekpub,
};
use alloc::vec::Vec;
#[cfg(all(feature = "vtpm", not(test)))]
use core::slice::from_raw_parts_mut;
use core::{mem::size_of, slice::from_raw_parts};
#[cfg(all(feature = "vtpm", not(test)))]
use sha2::{Digest, Sha512};
const SVSM_ATTEST_SERVICES: u32 = 0;
const SVSM_ATTEST_SINGLE_SERVICE: u32 = 1;

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
        // get_nonce_gpa_and_size() already validated that gpa is page
        // aligned, valid  and does not cross page boundary.
        let start = gpa.page_align();
        let offset = gpa.page_offset();

        let guard = PerCPUPageMappingGuard::create_4k(start)?;
        let vaddr = guard.virt_addr() + offset;

        // Check that the nonce length is not greater than 4k as we are going to map in only one
        // page. Nonce size is 64 bytes per Table 21 of
        // "SEV Secure Nested Paging Firmware ABI Specification, Revision 1.56"
        if size > PAGE_SIZE {
            return Err(SvsmReqError::invalid_parameter());
        }

        // SAFETY: vaddr points to a new mapped page region. And get_nonce_gpa_and_size() already
        // validated that gpa is page aligned, valid  and does not cross page boundaries. We also
        // checked earlier that size is not greater than PAGE_SIZE, so we can safely read the nonce.
        let buffer = unsafe { from_raw_parts(vaddr.as_mut_ptr::<u8>(), size) };
        let nonce = buffer.to_vec();

        Ok(nonce)
    }

    /// Returns the nonce GPA and size
    /// Checks if gpa is page aligned, valid  and does not cross page boundary.
    pub fn get_nonce_gpa_and_size(&self) -> Result<(PhysAddr, usize), SvsmReqError> {
        let gpa = PhysAddr::from(self.nonce_gpa);
        if !gpa.is_aligned(8) || !valid_phys_address(gpa) || gpa.crosses_page(8) {
            return Err(SvsmReqError::invalid_parameter());
        }

        // Won't panic on amd64 as usize > u32 always
        let size = self.nonce_size as usize;

        Ok((gpa, size))
    }

    /// Returns the manifest GPA and size
    /// Checks if gpa is page aligned, valid  and does not cross page boundary.
    pub fn get_manifest_gpa_and_size(&self) -> Result<(PhysAddr, usize), SvsmReqError> {
        let gpa = PhysAddr::from(self.manifest_gpa);
        if !gpa.is_aligned(8) || !valid_phys_address(gpa) || gpa.crosses_page(8) {
            return Err(SvsmReqError::invalid_parameter());
        }

        // Won't panic on amd64 as usize > u32 always
        let size = self.manifest_size as usize;

        Ok((gpa, size))
    }

    /// Returns the guid
    /// Checks if gpa is page aligned, valid  and does not cross page boundary
    pub fn get_report_gpa_and_size(&self) -> Result<(PhysAddr, usize), SvsmReqError> {
        let gpa = PhysAddr::from(self.report_gpa);
        if !gpa.is_aligned(8) || !valid_phys_address(gpa) || gpa.crosses_page(8) {
            return Err(SvsmReqError::invalid_parameter());
        }

        // Won't panic on amd64 as usize > u32 always
        let size = self.report_size as usize;

        Ok((gpa, size))
    }

    pub fn get_manifest_version(&self) -> u32 {
        self.manifest_ver
    }

    fn is_manifest_version_valid(&self) -> bool {
        //Currently only manifest version 0 is supported
        self.manifest_ver == 0
    }
    pub fn get_guid(&self) -> u128 {
        u128::from_le_bytes(self.guid)
    }
}

#[cfg(all(feature = "vtpm", not(test)))]
fn get_attestation_report(nonce: &[u8]) -> Result<Vec<u8>, SvsmReqError> {
    //Construct attestation request message to send to SNP
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
    let manifest = vtpm_get_ekpub()?;

    // Concatenate nonce and manifest and hash per page 29 of
    // "Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00".
    let nonce_and_manifest = [&nonce[..], &manifest[..]].concat();
    let hash = Sha512::digest(&nonce_and_manifest);

    // Get attestation report from PSP with Sha512(nonce||manifest) as REPORT_DATA.
    let report = get_attestation_report(hash.as_slice())?;
    // Validate that the report is not empty

    // Get attestation report buffer's gPA from call's Attest Single Service Operation structure
    let (report_gpa, _) = ops.get_report_gpa_and_size()?;
    let report_start = report_gpa.page_align();
    let report_offset = report_gpa.page_offset();

    let report_guard = PerCPUPageMappingGuard::create_4k(report_start)?;
    let report_vaddr = report_guard.virt_addr() + report_offset;

    // Check that the attestation report length is not greater than 4K as we going to map in one
    // page only below. If it is, return an error as something is wrong with the report or SNP
    // Per page 32 of "Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00",
    // return 0x8000_1000 i.e. SVSM::UNSUPPORTED_PROTOCOL.
    // The Attestation report length is 0x5F (95) per  Table 21 of
    // "SEV Secure Nested Paging Firmware ABI Specification, Revision 1.56"
    if report.len() > PAGE_SIZE {
        log::error!("Malformed VTPM service attestation report");
        return Err(SvsmReqError::unsupported_protocol());
    }

    // SAFETY: report_vaddr points to a new mapped region of size PAGE_SIZE. report_gpa is obtained
    // from a guest-provided physical address (untrusted), so it needs to be validated that it
    // belongs to the guest and only the guest. That was done inside get_report_gpa_and_size().
    // get_report_gpa_and_size() also validated that report_gpa is page aligned and does not cross
    // a page boundary.
    // Since we also checked that report.len() is not greater than PAGE_SIZE, we can safely write
    // the report to guest_report_buffer.
    let guest_report_buffer =
        unsafe { from_raw_parts_mut(report_vaddr.as_mut_ptr::<u8>(), PAGE_SIZE) };
    guest_report_buffer[..report.len()].copy_from_slice(&report);

    // Set report size in bytes in r8 register
    params.r8 = report.len() as u64;

    // Get manifest buffer's GPA from call's Attest Single Service Operation structure
    let (manifest_gpa, _) = ops.get_manifest_gpa_and_size()?;
    let manifest_start = manifest_gpa.page_align();
    let manifest_offset = manifest_gpa.page_offset();

    let manifest_guard = PerCPUPageMappingGuard::create_4k(manifest_start)?;
    let manifest_vaddr = manifest_guard.virt_addr() + manifest_offset;

    // Check that the length of the manifest is not greater than 4k as we going to map in one page
    // only. If it is, return an error as something is wrong with the manifest or vTPM
    // Per page 32 of Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00 July 2023
    // return SVSM::UNSUPPORTED_PROTOCOL (i.e., 0x8000_1000).
    // Per "TCG EK Credential Profile For TPM Family 2.0; Level 0  Version 2.5 Revision 2"
    // none of the TCG EK profiles will produce a manifest i.e. TPMT_PUBLIC larger than 4K.
    if manifest.len() > PAGE_SIZE {
        log::error!("Malformed VTPM service attestation manifest");
        return Err(SvsmReqError::unsupported_protocol());
    }

    // SAFETY: manifest_vaddr points to a new mapped region of size PAGE_SIZE. report_gpa is obtained
    // from a guest-provided physical address (untrusted), so it needs to be validated that it
    // belongs to the guest and only the guest. That was done inside get_manifest_gpa_and_size().
    // get_manifest_gpa_and_size() also validated that manifest_gpa is page aligned and does not cross
    // a page boundary.
    // Since we also checked that manifest.len() is not greater than PAGE_SIZE, we can safely write
    // the report to guest_manifest_buffer.
    let guest_manifest_buffer =
        unsafe { from_raw_parts_mut(manifest_vaddr.as_mut_ptr::<u8>(), PAGE_SIZE) };
    guest_manifest_buffer[..manifest.len()].copy_from_slice(&manifest);

    // Set the manifest size in bytes in rcx register
    params.rcx = manifest.len() as u64;

    // Does not support certificate currently, so setting certificate size to 0
    params.rdx = 0;

    Ok(())
}

fn attest_multiple_service(_params: &RequestParams) -> Result<(), SvsmReqError> {
    Err(SvsmReqError::unsupported_protocol())
}

#[allow(clippy::needless_pass_by_ref_mut)]
fn attest_single_service_handler(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // Get the gpa of Attest Single Service Operation structure
    let gpa = PhysAddr::from(params.rcx);

    if !gpa.is_aligned(8) || !valid_phys_address(gpa) || gpa.crosses_page(8) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let offset = gpa.page_offset();
    let paddr = gpa.page_align();

    // Map the Attest Single Service Operation structure page
    // Per Table 13 of the spec "Secure VM Service Module for SEV-SNP Guests
    // 58019 Rev. 1.00", we only need the first 0x58 bytes.
    let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
    let vaddr = guard.virt_addr() + offset;

    // SAFETY: The untrusted GPA from the guest is validated above as a valid address.
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
        SVSM_ATTEST_SERVICES => attest_multiple_service(params),
        SVSM_ATTEST_SINGLE_SERVICE => attest_single_service_handler(params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}
