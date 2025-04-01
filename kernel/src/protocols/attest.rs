// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Coconut-SVSM Authors
//

//! Attest protocol implementation

extern crate alloc;

use crate::address::{Address, PhysAddr};
use crate::crypto::digest::{Algorithm, Sha512};
use crate::error::{AttestError, SvsmError};
use crate::greq::{
    pld_report::{SnpReportRequest, SnpReportResponse},
    services::get_regular_report,
};
use crate::mm::guestmem::{copy_slice_to_guest, read_bytes_from_guest, read_from_guest};
use crate::protocols::{errors::SvsmReqError, RequestParams};
use crate::utils::MemoryRegion;

use alloc::{boxed::Box, vec::Vec};
use uuid::{uuid, Uuid};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

const SERVICES_MANIFEST_GUID: Uuid = uuid!("63849ebb-3d92-4670-a1ff-58f9c94b87bb");
const GUID_HEADER_ENTRY_SIZE: usize = 24;
const SVSM_ATTEST_SERVICES: u32 = 0;

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

fn get_attestation_report(nonce: &[u8]) -> Result<Box<SnpReportResponse>, SvsmReqError> {
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

fn write_report_and_manifest(
    manifest: &[u8],
    params: &mut RequestParams,
    ops: &AttestServicesOp,
    report: &[u8],
) -> Result<(), SvsmReqError> {
    // Get attestation report buffer's gPA from call's Attest Single Service Operation structure.
    // The buffer is required to be page aligned but can be bigger than 4K so can cross pages.
    // If it is bigger than 4K, it must be physically contiguous.
    let report_region = ops.get_report_region()?;

    // Get manifest buffer's GPA from call's Attest Single Service Operation structure
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

    // Does not support certificate currently, so setting certificate size to 0
    params.rdx = 0;

    Ok(())
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

    // ENUMERATE ALL SERVICES HERE

    let manifest = services.to_vec()?;
    let mut nonce_and_manifest = attest_op.get_nonce()?;
    nonce_and_manifest.extend_from_slice(manifest.as_slice());

    // Concatenate nonce and manifest and hash per page 29 of
    // "Secure VM Service Module for SEV-SNP Guests 58019 Rev. 1.00".
    let hash = Sha512::digest(&nonce_and_manifest);

    // Get attestation report from PSP with Sha512(nonce||manifest) as REPORT_DATA.
    let resp = get_attestation_report(hash.as_slice())?;

    write_report_and_manifest(
        manifest.as_slice(),
        params,
        &attest_op,
        resp.report.as_bytes(),
    )
}

pub fn attest_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_ATTEST_SERVICES => attest_multiple_services(params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}
