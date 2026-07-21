// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

//! OCP protocol implementation (SVSM draft spec).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{
    address::{Address, PhysAddr},
    locking::RWLock,
    mm::{GuestPtr, PerCPUPageMappingGuard, guestmem::copy_slice_to_guest, valid_phys_region},
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
    utils::MemoryRegion,
};

use bitfield_struct::bitfield;
use core::sync::atomic::{AtomicU32, Ordering};
use core::{fmt::Debug, mem};
use release::COCONUT_VERSION;
use zerocopy::{Immutable, IntoBytes};

const OCP_SOURCE_NAME_LEN: usize = 112;
const OCP_SOURCE_ENTRY_SIZE: usize = 128;
const OCP_SOURCE_DETAILS_SIZE: usize = 12;

// OCP protocol services
const SVSM_OCP_LIST_OBJECTS: u32 = 0;
const SVSM_OCP_LIST_OBJECT_SOURCES: u32 = 1;
const SVSM_OCP_READ: u32 = 2;
const SVSM_OCP_WRITE: u32 = 3;

const LOW_32_BITS: u64 = 0xffff_ffff;

const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

// Min and Max supported protocol version
pub const OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MIN: u32 = 1;
pub const OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MAX: u32 = 1;

#[bitfield(u32)]
#[derive(IntoBytes, Immutable)]
struct OcpSourceFlags {
    writable: bool,
    #[bits(31)]
    _rsvd_31_1: u32,
}

#[repr(u32)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of data the OCP source contains.
pub enum OcpSourceType {
    StaticString = 0,
    Integer = 1,
}

/// OCP source entry structure.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpSource {
    /// Super index of the source
    sup_index: u32,
    /// Sub index of the source
    sub_index: u32,
    /// Type of the source.
    kind: OcpSourceType,
    /// Source flags.
    flags: OcpSourceFlags,
    /// Name of the source encoded as UTF-8.
    name: [u8; OCP_SOURCE_NAME_LEN],
}

impl OcpSource {
    pub fn new(
        sup_index: u32,
        sub_index: u32,
        writable: bool,
        name: &str,
        kind: OcpSourceType,
    ) -> Self {
        let mut name_bytes = [0u8; OCP_SOURCE_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len();

        if len == 0 || len >= OCP_SOURCE_NAME_LEN {
            // Failure if the length is greater than that value as we want
            // a null terminated string.
            panic!("Name length must not be zero nor exceed {OCP_SOURCE_NAME_LEN} bytes");
        }

        name_bytes[..len].copy_from_slice(bytes);

        Self {
            sup_index,
            sub_index,
            kind,
            flags: OcpSourceFlags::new().with_writable(writable),
            name: name_bytes,
        }
    }
}

const _: () = assert!(
    mem::offset_of!(OcpSource, sup_index) == 0x00
        && mem::offset_of!(OcpSource, sub_index) == 0x04
        && mem::offset_of!(OcpSource, kind) == 0x08
        && mem::offset_of!(OcpSource, flags) == 0x0C
        && mem::offset_of!(OcpSource, name) == 0x10
        && mem::size_of::<OcpSource>() == OCP_SOURCE_ENTRY_SIZE
);

#[repr(u32)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of objects the SVSM contains.
pub enum OcpObjectType {
    Svsm = 0,
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpObjectDetails {
    category: OcpObjectType,
    index: u32,
    count: u32,
}

/// Operations required for an OCP object
pub trait OcpObjectOperations: Debug + Send + Sync {
    fn read(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn write(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn get_object_details(&self) -> &OcpObjectDetails;
    fn get_object_sources(&self) -> &[OcpSource];
}

static OCP_SOURCES: RWLock<BTreeMap<u32, Arc<dyn OcpObjectOperations>>> =
    RWLock::new(BTreeMap::new());

pub fn add_ocp_object(sup_index: u32, source: Arc<dyn OcpObjectOperations>) {
    //todo: return error when index is already taken or
    //todo: implement a way to get the first free index
    //      similar to get first free port in VsockDriver?
    //      I need to do it before adding the source as each
    //      entry should have that index inside

    let mut map = OCP_SOURCES.lock_write();

    if map.contains_key(&sup_index) {
        panic!("Super index already defined");
    }

    let _ = map.insert(sup_index, source);
}

fn ocp_list_objects_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let num_entries = (params.r8 & LOW_32_BITS) as usize;
    let first = (params.rcx & LOW_32_BITS) as usize;

    if num_entries == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    let map = OCP_SOURCES.lock_read();

    let map_len = map.len();

    let end = (first + num_entries).min(map_len);

    let mut entries_to_return = end - first;
    // Real buffer size is not inside request params, so
    // compute it based on the number of entries and
    // the size of each entry
    let buffer_size = entries_to_return * OCP_SOURCE_DETAILS_SIZE;

    if buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let region =
        MemoryRegion::checked_new(gpa_buffer, buffer_size).ok_or(SvsmReqError::invalid_address())?;
    if !valid_phys_region(&region) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let base_paddr = gpa_buffer.page_align();
    let offset = gpa_buffer.page_offset();
    let end_paddr = region.end().page_align_up();

    let guard = PerCPUPageMappingGuard::create(base_paddr, end_paddr, 0)?;
    let base_vaddr = guard.virt_addr();

    let mut guest_entry = GuestPtr::<OcpObjectDetails>::new(base_vaddr + offset);

    for (i, (_key, entry)) in map
        .range(first as u32..)
        .take(entries_to_return)
        .enumerate()
    {
        // SAFETY: guest_entry is obtained from an untrusted GPA.
        // The address is checked using with valid_phys_region()
        // to ensure it is not assigned to SVSM.
        if unsafe { guest_entry.write_ref(entry.get_object_details()) }.is_err() {
            // fixme: is it correct that the write can fail mid loop
            // and some entries have already been written?
            entries_to_return = i;
            break;
        }
        guest_entry = guest_entry.offset(1);
    }

    params.rcx = entries_to_return as u64;

    Ok(())
}

fn ocp_list_object_sources_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let num_entries = (params.r8 & LOW_32_BITS) as usize;
    let first = (params.rcx & LOW_32_BITS) as usize;
    let sup_index = ((params.rcx & !LOW_32_BITS) >> 32) as u32;

    if num_entries == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    let map = OCP_SOURCES.lock_read();

    let Some(object) = map.get(&sup_index) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    let num_sources = object.get_object_details().count;

    let end = (first + num_entries).min(num_sources as usize);

    let mut entries_to_return = end - first;
    // Real buffer size is not inside request params, so
    // compute it based on the number of entries and
    // the size of each entry
    let buffer_size = entries_to_return * OCP_SOURCE_ENTRY_SIZE;

    if buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let region =
        MemoryRegion::checked_new(gpa_buffer, buffer_size).ok_or(SvsmReqError::invalid_address())?;
    if !valid_phys_region(&region) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let base_paddr = gpa_buffer.page_align();
    let offset = gpa_buffer.page_offset();
    let end_paddr = region.end().page_align_up();

    let guard = PerCPUPageMappingGuard::create(base_paddr, end_paddr, 0)?;
    let base_vaddr = guard.virt_addr();

    let mut guest_entry = GuestPtr::<OcpSource>::new(base_vaddr + offset);

    for (i, entry) in object.get_object_sources().iter().enumerate() {
        // SAFETY: guest_entry is obtained from an untrusted GPA.
        // The address is checked using with valid_phys_region()
        // to ensure it is not assigned to SVSM.
        if unsafe { guest_entry.write_ref(entry) }.is_err() {
            // fixme: is it correct that the write can fail mid loop
            // and some entries have already been written?
            entries_to_return = i;
            break;
        }
        guest_entry = guest_entry.offset(1);
    }

    params.rcx = entries_to_return as u64;

    Ok(())
}

fn ocp_read_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let sub_index = (params.rcx & LOW_32_BITS) as u32;
    let sup_index = ((params.rcx & !LOW_32_BITS) >> 32) as u32;
    let bytes_to_read = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if bytes_to_read == 0 {
        params.r8 = 0;
        return Ok(());
    }

    if bytes_to_read as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let map = OCP_SOURCES.lock_read();

    let Some(source) = map.get(&sup_index) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    let bytes_copied = source.read(offset, gpa_buffer, bytes_to_read, sub_index)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

fn ocp_write_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let sub_index = (params.rcx & LOW_32_BITS) as u32;
    let sup_index = ((params.rcx & !LOW_32_BITS) >> 32) as u32;
    let bytes_to_write = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if bytes_to_write as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let map = OCP_SOURCES.lock_read();

    let Some(source) = map.get(&sup_index) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    if bytes_to_write == 0 {
        params.r8 = 0;
        return Ok(());
    }

    let bytes_copied = source.write(offset, gpa_buffer, bytes_to_write, sub_index)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST_OBJECTS => ocp_list_objects_request(params),
        SVSM_OCP_LIST_OBJECT_SOURCES => ocp_list_object_sources_request(params),
        SVSM_OCP_READ => ocp_read_request(params),
        SVSM_OCP_WRITE => ocp_write_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}

#[derive(Debug)]
struct OcpSvsmObject {
    ocp_source_entries: Vec<OcpSource>,
    details: OcpObjectDetails,
    state: AtomicU32,
}

impl OcpSvsmObject {
    const fn new(category: OcpObjectType, sup_index: u32) -> Self {
        Self {
            ocp_source_entries: Vec::new(),
            details: OcpObjectDetails {
                category,
                index: sup_index,
                count: 0,
            },
            state: AtomicU32::new(0),
        }
    }

    fn add_source(&mut self, source: OcpSource) {
        self.ocp_source_entries.push(source);
        self.details.count += 1;
    }
}

impl OcpObjectOperations for OcpSvsmObject {
    fn read(
        &self,
        offset: u32,
        gpa: PhysAddr,
        size: u32,
        sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        let bytes_read = match sub_index {
            0 => {
                // fixme: heap allocation
                let version_str = format!("{COCONUT_VERSION}\0");
                let version_bytes = version_str.as_bytes();
                let len = version_bytes.len();

                if offset as usize >= len {
                    return Ok(0);
                }

                let end = (offset as usize + size as usize).min(len);

                let bytes_to_copy = end - offset as usize;

                let version_slice = &version_bytes[offset as usize..end];

                copy_slice_to_guest(version_slice, gpa)?;

                bytes_to_copy as u32
            }
            1 => {
                // simplified read implementation for testing purposes
                let state = self.state.load(Ordering::Acquire);
                let state_bytes = state.to_le_bytes();

                copy_slice_to_guest(&state_bytes, gpa)?;

                4
            }
            _ => {
                return Err(SvsmReqError::invalid_parameter());
            }
        };

        Ok(bytes_read)
    }

    fn write(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        let bytes_written = match sub_index {
            1 => {
                // simplified write implementation for testing purposes
                let current_state = self.state.load(Ordering::Acquire);
                self.state.store(current_state + 1, Ordering::Release);
                4
            }
            _ => {
                return Err(SvsmReqError::invalid_parameter());
            }
        };
        Ok(bytes_written)
    }

    fn get_object_sources(&self) -> &[OcpSource] {
        self.ocp_source_entries.as_slice()
    }

    fn get_object_details(&self) -> &OcpObjectDetails {
        &self.details
    }
}

pub fn add_svsm_object() {
    // TODO: get first free index from an atomic counter?

    let mut svsm_obj = OcpSvsmObject::new(OcpObjectType::Svsm, 0);

    let svsm_version = OcpSource::new(0, 0, false, "svsm_version", OcpSourceType::StaticString);
    svsm_obj.add_source(svsm_version);

    let write_source = OcpSource::new(0, 1, true, "write_source", OcpSourceType::Integer);
    svsm_obj.add_source(write_source);

    add_ocp_object(0, Arc::new(svsm_obj));
}
