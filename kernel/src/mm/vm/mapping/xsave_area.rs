// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2024 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use super::VirtualMapping;
use crate::address::PhysAddr;
use crate::cpu::sse::get_xsave_area_size;
use crate::error::SvsmError;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::vm::RawAllocMapping;

#[derive(Debug)]
pub struct XSaveArea {
    alloc: RawAllocMapping,
}

impl XSaveArea {
    pub fn new() -> Result<Self, SvsmError> {
        let size = get_xsave_area_size();
        let mut xsa = XSaveArea {
            alloc: RawAllocMapping::new(size as usize),
        };
        xsa.alloc.alloc_pages()?;
        Ok(xsa)
    }
}

impl VirtualMapping for XSaveArea {
    fn mapping_size(&self) -> usize {
        self.alloc.mapping_size()
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        self.alloc.map(offset)
    }

    fn unmap(&self, _offset: usize) {
        // Nothing for now
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        PTEntryFlags::WRITABLE | PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }
}
