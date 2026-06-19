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
    mm::{GuestPtr, ptguards::PerCPUPageMappingGuard},
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
};

use core::ffi::CStr;

// OCP protocol services
const SVSM_OCP_LIST: u32 = 0;
const SVSM_OCP_READ: u32 = 1;

const LOW_32_BITS: u64 = 0xffff_ffff;
const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

static OCP_OBJECTS: RWLock<Vec<Arc<dyn OcpObject>>> = RWLock::new(Vec::new());

pub fn add_ocp_object(object: Arc<dyn OcpObject>) {
    // todo: check unique name here
    let mut objects = OCP_OBJECTS.lock_write();
    objects.push(object);
}

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
    let mut name_slice = [0u8; OCP_NAME_LEN];
    let name_guard = PerCPUPageMappingGuard::create(
        gpa_obj_name.page_align(),
        gpa_obj_name
            .checked_add(OCP_NAME_LEN)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let name_ptr = name_guard.guest_slice::<u8>(gpa_obj_name.page_offset(), OCP_NAME_LEN)?;
    name_ptr.read_to_slice(&mut name_slice)?;

    let obj_name = CStr::from_bytes_until_nul(&name_slice)
        .map_err(|_| SvsmReqError::invalid_parameter())?
        .to_str()
        .map_err(|_| SvsmReqError::invalid_parameter())?;

    get_ocp_object(obj_name).ok_or(SvsmReqError::invalid_parameter())
}

/// Retrieve the identifier name from guest memory and extract the corresponding source
fn get_requested_source(gpa_id: PhysAddr) -> Result<Arc<dyn OcpSource>, SvsmReqError> {
    let mut id_slice = [0u8; OCP_IDENTIFIER_LEN];

    let id_guard = PerCPUPageMappingGuard::create(
        gpa_id.page_align(),
        gpa_id
            .checked_add(OCP_IDENTIFIER_LEN)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let id_ptr = id_guard.guest_slice::<u8>(gpa_id.page_offset(), OCP_IDENTIFIER_LEN)?;
    id_ptr.read_to_slice(&mut id_slice)?;

    let (obj_name, source_name) = CStr::from_bytes_until_nul(&id_slice)
        .map_err(|_| SvsmReqError::invalid_parameter())?
        .to_str()
        .map_err(|_| SvsmReqError::invalid_parameter())?
        .split_once('/')
        .ok_or(SvsmReqError::invalid_parameter())?;

    let Some(object) = get_ocp_object(obj_name) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    object
        .get_source(source_name)
        .ok_or(SvsmReqError::invalid_parameter())
}

fn list_objects_info(
    entries_ptr: GuestPtr<'_, [OcpSourceInfo]>,
    num_entries: usize,
) -> Result<(usize, usize), SvsmReqError> {
    let mut entries_written = 0;

    let objects = OCP_OBJECTS.lock_read();
    let objects_len = objects.len();

    for entry in objects.iter() {
        if entries_written >= num_entries {
            break;
        }
        if entries_ptr
            .write(entries_written, entry.get_info())
            .is_err()
        {
            break;
        }
        entries_written += 1;
    }
    Ok((entries_written, objects_len))
}

fn list_object_sources(
    entries_ptr: GuestPtr<'_, [OcpSourceInfo]>,
    gpa_obj_name: PhysAddr,
    num_entries: usize,
) -> Result<(usize, usize), SvsmReqError> {
    let object = get_requested_object(gpa_obj_name)?;

    let sources_len = object.get_source_count();

    let mut entries_written = 0;

    for entry in object.get_sources() {
        if entries_written >= num_entries {
            break;
        }
        if entries_ptr
            .write(entries_written, entry.get_info())
            .is_err()
        {
            break;
        }
        entries_written += 1;
    }
    Ok((entries_written, sources_len))
}

fn ocp_list_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_object_name = PhysAddr::from(params.rcx);

    let buffer_size = (params.r8 & LOW_32_BITS) as usize;

    if buffer_size == 0 || buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    if !buffer_size.is_multiple_of(OCP_SOURCE_SIZE) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let num_entries = buffer_size / OCP_SOURCE_SIZE;

    let guard = PerCPUPageMappingGuard::create(
        gpa_buffer.page_align(),
        gpa_buffer
            .checked_add(buffer_size)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let entries_ptr = guard.guest_slice::<OcpSourceInfo>(gpa_buffer.page_offset(), num_entries)?;

    let (entries_written, total_entries) = if gpa_object_name.is_null() {
        list_objects_info(entries_ptr, num_entries)?
    } else {
        list_object_sources(entries_ptr, gpa_object_name, num_entries)?
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
    let bytes_to_read = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if bytes_to_read as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let source = get_requested_source(gpa_id)?;

    if bytes_to_read == 0 {
        params.r8 = 0;
        return Ok(());
    }

    if !source.get_info().is_valid_access(offset, bytes_to_read) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let bytes_copied = source.read(offset, gpa_buffer, bytes_to_read)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST => ocp_list_request(params),
        SVSM_OCP_READ => ocp_read_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
