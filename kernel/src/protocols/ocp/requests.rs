// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use crate::{
    address::{Address, PhysAddr},
    mm::{GuestPtr, guestmem::checked_guest_region_guard},
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
};

use super::details::{OCP_SOURCE_DETAILS_SIZE, OcpObjectDetails};
use super::map::explore_map;

// OCP protocol services
const SVSM_OCP_LIST_OBJECTS: u32 = 0;

const LOW_32_BITS: u64 = 0xffff_ffff;
const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

fn ocp_list_objects_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let num_entries = (params.r8 & LOW_32_BITS) as u32;
    let first = (params.rcx & LOW_32_BITS) as u32;

    if num_entries == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    // Real buffer size is not inside request params, so
    // compute it based on the number of entries and
    // the size of each entry
    let buffer_size = (num_entries as usize) * OCP_SOURCE_DETAILS_SIZE;

    if buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let guard = checked_guest_region_guard(gpa_buffer, buffer_size)?;
    let guest_vaddr = guard.virt_addr() + gpa_buffer.page_offset();

    let mut guest_entry = GuestPtr::<OcpObjectDetails>::new(guest_vaddr);

    let mut entries_to_return = 0;

    for entry in explore_map(first, num_entries)?.iter() {
        // SAFETY: guest_entry is obtained from an untrusted GPA.
        // The address is checked using with valid_phys_region()
        // to ensure it is not assigned to SVSM.
        if unsafe { guest_entry.write_ref(entry.get_object_details()) }.is_err() {
            // fixme: is it correct that the write can fail mid loop
            // and some entries have already been written?
            break;
        }
        entries_to_return += 1;
        guest_entry = guest_entry.offset(1);
    }

    params.rcx = entries_to_return;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST_OBJECTS => ocp_list_objects_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
