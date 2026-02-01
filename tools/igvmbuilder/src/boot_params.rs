// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use igvm_defs::PAGE_SIZE_4K;

#[derive(Clone, Copy, Debug)]
pub enum BootParamType {
    General,
    MemoryMap,
    Madt,
    GuestContext,
}

#[derive(Debug)]
pub struct BootParamLayout {
    general_param_offset: u32,
    memory_map_offset: u32,
    madt_offset: u32,
    guest_context_offset: u32,
    guest_context_size: u32,
    total_size: u32,
}

impl BootParamLayout {
    pub fn new(include_guest_context: bool) -> Self {
        let page_size = PAGE_SIZE_4K as u32;
        // If a guest context is present, it is the first parameter page after
        // the parameter block header.  Otherwise, no space is consumed.
        let (guest_context_offset, guest_context_size) = if include_guest_context {
            (page_size, page_size)
        } else {
            (0, 0)
        };
        let general_param_offset = page_size + guest_context_size;
        let madt_offset = general_param_offset + page_size;
        let memory_map_offset = madt_offset + page_size;
        let total_size = memory_map_offset + page_size;
        Self {
            general_param_offset,
            memory_map_offset,
            madt_offset,
            guest_context_offset,
            guest_context_size,
            total_size,
        }
    }

    pub fn total_size(&self) -> u32 {
        self.total_size
    }

    pub fn get_param_offset(&self, param_type: BootParamType) -> u32 {
        match param_type {
            BootParamType::General => self.general_param_offset,
            BootParamType::MemoryMap => self.memory_map_offset,
            BootParamType::Madt => self.madt_offset,
            BootParamType::GuestContext => self.guest_context_offset,
        }
    }

    pub fn get_param_size(&self, param_type: BootParamType) -> u32 {
        match param_type {
            BootParamType::GuestContext => self.guest_context_size,
            _ => {
                // All other parameter types are currently a single page.
                PAGE_SIZE_4K as u32
            }
        }
    }

    pub fn get_param_gpa(&self, param_base_gpa: u64, param_type: BootParamType) -> u64 {
        param_base_gpa + self.get_param_offset(param_type) as u64
    }
}
