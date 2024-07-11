// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2024 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use super::VirtualMapping;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::mm::alloc::allocate_file_page_ref;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::{PageRef, PAGE_SIZE};

#[derive(Debug)]
pub struct XSaveArea {
    pg: PageRef,
}

impl XSaveArea {
    pub fn new() -> Result<Self, SvsmError> {
        let pg = allocate_file_page_ref()?;
        let xsa = XSaveArea { pg };
        Ok(xsa)
    }
}

impl VirtualMapping for XSaveArea {
    fn mapping_size(&self) -> usize {
        PAGE_SIZE
    }

    fn map(&self, _offset: usize) -> Option<PhysAddr> {
        Some(self.pg.phys_addr())
    }

    fn unmap(&self, _offset: usize) {
        // Nothing for now
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        PTEntryFlags::WRITABLE | PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }
}
