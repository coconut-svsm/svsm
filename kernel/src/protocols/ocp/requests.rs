// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use crate::{
    address::{Address, PhysAddr},
    mm::ptguards::PerCPUPageMappingGuard,
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
};

use super::details::{
    OCP_OBJECT_DETAILS_SIZE, OCP_SOURCE_DETAILS_SIZE, OcpObjectDetails, OcpSourceDetails,
};
use super::map::{explore_map, get_object};

// OCP protocol services
const SVSM_OCP_LIST_OBJECTS: u32 = 0;
const SVSM_OCP_LIST_OBJECT_SOURCES: u32 = 1;
const SVSM_OCP_READ: u32 = 2;

const LOW_32_BITS: u64 = 0xffff_ffff;
const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

fn ocp_list_objects_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let buffer_size = (params.r8 & LOW_32_BITS) as usize;
    let first = (params.rcx & LOW_32_BITS) as u32;

    if buffer_size == 0 || buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    if buffer_size % OCP_OBJECT_DETAILS_SIZE != 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    let num_entries = (buffer_size / OCP_OBJECT_DETAILS_SIZE) as u32;

    let guard = PerCPUPageMappingGuard::create(
        gpa_buffer.page_align(),
        gpa_buffer
            .checked_add(buffer_size)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let entries_ptr =
        guard.guest_slice::<OcpObjectDetails>(gpa_buffer.page_offset(), num_entries as usize)?;

    let mut entries_written = 0;

    for entry in explore_map(first, num_entries)?.iter() {
        // fixme: is it correct that the write can fail mid loop
        // and some entries have already been written?
        if entries_ptr
            .write(entries_written, entry.get_object_details())
            .is_err()
        {
            break;
        }
        entries_written += 1;
    }

    params.rcx = (entries_written * OCP_OBJECT_DETAILS_SIZE) as u64;

    Ok(())
}

fn ocp_list_object_sources_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let buffer_size = (params.r8 & LOW_32_BITS) as usize;
    let first = (params.rcx & LOW_32_BITS) as u32;
    let sup_index = ((params.rcx & !LOW_32_BITS) >> 32) as u32;

    if buffer_size == 0 || buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    if buffer_size % OCP_SOURCE_DETAILS_SIZE != 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    let num_entries = (buffer_size / OCP_SOURCE_DETAILS_SIZE) as u32;

    let Some(object) = get_object(sup_index) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    let guard = PerCPUPageMappingGuard::create(
        gpa_buffer.page_align(),
        gpa_buffer
            .checked_add(buffer_size)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let entries_ptr =
        guard.guest_slice::<OcpSourceDetails>(gpa_buffer.page_offset(), num_entries as usize)?;

    let mut entries_written = 0;

    for entry in object.get_object_sources(first, num_entries) {
        // fixme: is it correct that the write can fail mid loop
        // and some entries have already been written?
        if entries_ptr
            .write(entries_written, entry.get_source_details())
            .is_err()
        {
            break;
        }
        entries_written += 1;
    }

    params.rcx = (entries_written * OCP_SOURCE_DETAILS_SIZE) as u64;

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

    if bytes_to_read as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let Some(object) = get_object(sup_index) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    if bytes_to_read == 0 {
        params.r8 = 0;
        return Ok(());
    }

    let bytes_copied = object.read(offset, gpa_buffer, bytes_to_read, sub_index)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST_OBJECTS => ocp_list_objects_request(params),
        SVSM_OCP_LIST_OBJECT_SOURCES => ocp_list_object_sources_request(params),
        SVSM_OCP_READ => ocp_read_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
