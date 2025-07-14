// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

extern crate alloc;
use alloc::vec::Vec;

use crate::address::PhysAddr;
use crate::locking::SpinLock;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::utils::MemoryRegion;

const SVSM_REQ_MEMMAP_NUM_ENTRIES: u32 = 1;
const SVSM_REQ_MEMMAP_GET_ENTRY: u32 = 2;

pub const MEMMAP_PROTOCOL_VERSION_MIN: u32 = 1;
pub const MEMMAP_PROTOCOL_VERSION_MAX: u32 = 1;

enum MemmapEntryType {
    Memory,
    Reserved,
}

struct MemmapEntry {
    entry_type: MemmapEntryType,
    region: MemoryRegion<PhysAddr>,
}

static MEMMAP: SpinLock<Vec<MemmapEntry>> = SpinLock::new(Vec::new());

fn memmap_num_entries(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let memmap = MEMMAP.lock();
    params.rcx = memmap.len() as u64;
    Ok(())
}

fn memmap_get_entry(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let memmap = MEMMAP.lock();
    let Some(entry) = memmap.get(params.rcx as usize) else {
        return Err(SvsmReqError::invalid_parameter());
    };
    params.rdx = match entry.entry_type {
        MemmapEntryType::Memory => 1,   // EfiAcpiAddressRangeMemory
        MemmapEntryType::Reserved => 2, // EfiAcpiAddressRangeReserved
    };
    params.r8 = u64::from(entry.region.start());
    params.r9 = entry.region.len() as u64;
    Ok(())
}

pub fn memmap_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_REQ_MEMMAP_NUM_ENTRIES => memmap_num_entries(params),
        SVSM_REQ_MEMMAP_GET_ENTRY => memmap_get_entry(params),

        _ => Err(SvsmReqError::unsupported_call()),
    }
}

fn memmap_protocol_add_region(entry_type: MemmapEntryType, region: &MemoryRegion<PhysAddr>) {
    let entry = MemmapEntry {
        entry_type,
        region: region.clone(),
    };

    let mut memmap = MEMMAP.lock();
    memmap.push(entry);
}

pub fn memmap_protocol_add_memory(region: &MemoryRegion<PhysAddr>) {
    memmap_protocol_add_region(MemmapEntryType::Memory, region)
}

pub fn memmap_protocol_add_reserved(region: &MemoryRegion<PhysAddr>) {
    memmap_protocol_add_region(MemmapEntryType::Reserved, region)
}
