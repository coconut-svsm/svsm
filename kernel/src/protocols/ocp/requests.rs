// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use super::source::{
    OCP_IDENTIFIER_LEN, OCP_NAME_LEN, OCP_SOURCE_SIZE, OcpObject, OcpSource, OcpSourceInfo,
};
use crate::{
    address::{Address, PhysAddr},
    locking::RWLock,
    mm::{GuestPtr, guestmem::read_from_guest, ptguards::PerCPUPageMappingGuard},
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
};

use core::ffi::CStr;

// OCP protocol services
const SVSM_OCP_LIST: u32 = 0;
const SVSM_OCP_READ: u32 = 1;
const SVSM_OCP_WRITE: u32 = 2;

const LOW_32_BITS: u64 = 0xffff_ffff;
const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

// Min and Max supported protocol version
pub const OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MIN: u32 = 1;
pub const OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MAX: u32 = 1;

static OCP_OBJECTS: RWLock<Vec<Arc<dyn OcpObject>>> = RWLock::new(Vec::new());

/// Adds an OCP object to the global list if there is not already one with the same name.
pub fn add_ocp_object(object: Arc<dyn OcpObject>) -> bool {
    let new_obj_name = object.get_name();
    let mut objects = OCP_OBJECTS.lock_write();
    for obj in objects.iter() {
        if obj.get_name() == new_obj_name {
            return false;
        }
    }
    objects.push(object);
    true
}

/// Returns the OCP object with the given name, if it exists.
pub fn get_ocp_object(name: &str) -> Option<Arc<dyn OcpObject>> {
    let objects = OCP_OBJECTS.lock_read();
    for obj in objects.iter() {
        if obj.get_name() == name {
            return Some(obj.clone());
        }
    }
    None
}

/// Retrieve the object name from guest memory and extract the corresponding object
fn get_requested_object(gpa_obj_name: PhysAddr) -> Result<Arc<dyn OcpObject>, SvsmReqError> {
    let name_slice = read_from_guest::<[u8; OCP_NAME_LEN]>(gpa_obj_name)?;

    let obj_name = CStr::from_bytes_until_nul(&name_slice)
        .ok()
        .and_then(|s| s.to_str().ok())
        .ok_or(SvsmReqError::invalid_parameter())?;

    get_ocp_object(obj_name).ok_or(SvsmReqError::invalid_parameter())
}

/// Retrieve the identifier name from guest memory and extract the corresponding source
fn get_requested_source(gpa_id: PhysAddr) -> Result<Arc<dyn OcpSource>, SvsmReqError> {
    let id_slice = read_from_guest::<[u8; OCP_IDENTIFIER_LEN]>(gpa_id)?;

    let (obj_name, source_name) = CStr::from_bytes_until_nul(&id_slice)
        .ok()
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.split_once('/'))
        .ok_or(SvsmReqError::invalid_parameter())?;

    let Some(object) = get_ocp_object(obj_name) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    object
        .get_source(source_name)
        .ok_or(SvsmReqError::invalid_parameter())
}

/// Writes information about the available OCP objects to guest memory.
///
/// Up to `num_entries` entries are written to `entries_ptr`.
/// Returns the number of entries written and the total number of objects.
///
/// If writing an entry to guest memory fails, the error is returned
/// together with the other two values as previous entries may have been
/// successfully written and the result can therefore be shared with the guest.
fn list_objects_info(
    entries_ptr: GuestPtr<'_, [OcpSourceInfo]>,
    num_entries: usize,
) -> Result<(usize, usize), (SvsmReqError, usize, usize)> {
    let mut entries_written = 0;

    let objects = OCP_OBJECTS.lock_read();
    let objects_len = objects.len();

    for entry in objects.iter().take(num_entries) {
        entries_ptr
            .write(entries_written, entry.get_info())
            .map_err(|e| (SvsmReqError::from(e), entries_written, objects_len))?;
        entries_written += 1;
    }
    Ok((entries_written, objects_len))
}

/// Writes information about the sources of a requested OCP object to guest memory.
///
/// Up to `num_entries` entries are written to `entries_ptr`.
/// Returns the number of entries written and the total number of sources
/// of the requested object.
///
/// If writing an entry to guest memory fails, the error is returned
/// together with the other two values as previous entries may have been
/// successfully written and the result can therefore be shared with the guest.
fn list_object_sources_info(
    entries_ptr: GuestPtr<'_, [OcpSourceInfo]>,
    gpa_obj_name: PhysAddr,
    num_entries: usize,
) -> Result<(usize, usize), (SvsmReqError, usize, usize)> {
    let object = get_requested_object(gpa_obj_name).map_err(|e| (e, 0, 0))?;

    let sources_len = object.get_source_count();

    if num_entries == 0 {
        return Ok((0, sources_len));
    }

    let mut entries_written = 0;

    object
        .for_each_source(&mut |source| {
            entries_ptr.write(entries_written, source.get_info())?;
            entries_written += 1;
            Ok(entries_written != num_entries)
        })
        .map_err(|e| (e, entries_written, sources_len))?;

    Ok((entries_written, sources_len))
}

fn ocp_list_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_object_name = PhysAddr::from(params.rcx);

    let buffer_size = (params.r8 & LOW_32_BITS) as usize;

    if buffer_size == 0
        || buffer_size > OCP_BUFFER_MAX_SIZE
        || !buffer_size.is_multiple_of(OCP_SOURCE_SIZE)
    {
        return Err(SvsmReqError::invalid_parameter());
    }

    let num_entries = buffer_size / OCP_SOURCE_SIZE;

    let guard = PerCPUPageMappingGuard::create(
        gpa_buffer.page_align(),
        gpa_buffer
            .checked_add(buffer_size)
            .and_then(|end| end.checked_page_align_up())
            .ok_or(SvsmReqError::invalid_parameter())?,
        0,
    )?;

    let entries_ptr = guard.guest_slice::<OcpSourceInfo>(gpa_buffer.page_offset(), num_entries)?;

    let result = if gpa_object_name.is_null() {
        list_objects_info(entries_ptr, num_entries)
    } else {
        list_object_sources_info(entries_ptr, gpa_object_name, num_entries)
    };

    let (entries_written, total_entries) = match result {
        Ok(values) => values,
        // In this branch, no entries means the object was not found
        Err((e, _, 0)) => return Err(e),
        Err((e, entries, total)) => {
            log::error!("Failed to write one entries to guest memory: {e:?}");
            (entries, total)
        }
    };

    params.r8 = (entries_written * OCP_SOURCE_SIZE) as u64;
    params.r9 = (total_entries * OCP_SOURCE_SIZE) as u64;

    Ok(())
}

fn ocp_read_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_id = PhysAddr::from(params.rcx);
    let num_bytes = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if num_bytes as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let source = get_requested_source(gpa_id)?;

    if !source.get_info().is_valid_access(offset, num_bytes) {
        return Err(SvsmReqError::invalid_parameter());
    }

    if num_bytes == 0 {
        params.r8 = 0;
        return Ok(());
    }

    let bytes_copied = source.write_to_guest(offset, gpa_buffer, num_bytes)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

fn ocp_write_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_id = PhysAddr::from(params.rcx);
    let num_bytes = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if num_bytes as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let source = get_requested_source(gpa_id)?;

    let source_info = source.get_info();
    if !source_info.is_valid_access(offset, num_bytes) || !source_info.is_writable() {
        return Err(SvsmReqError::invalid_parameter());
    }

    let bytes_copied = source.read_from_guest(offset, gpa_buffer, num_bytes)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST => ocp_list_request(params),
        SVSM_OCP_READ => ocp_read_request(params),
        SVSM_OCP_WRITE => ocp_write_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
