// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::mm::alloc::{allocate_file_page_ref, PageRef};
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::utils::align_up;

extern crate alloc;
use alloc::vec::Vec;

/// Contains base functionality for all [`VirtualMapping`](super::api::VirtualMapping)
/// types which use self-allocated PageFile pages.
#[derive(Default, Debug)]
pub struct RawAllocMapping {
    /// A vec containing references to PageFile allocations
    pages: Vec<PageRef>,

    /// Number of pages required in `pages`
    count: usize,
}

impl RawAllocMapping {
    /// Creates a new instance of RawAllocMapping
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the mapping in bytes
    ///
    /// # Returns
    ///
    /// New instance of RawAllocMapping. Still needs to call `alloc_pages()` on it before it can be used.
    pub fn new(size: usize) -> Self {
        let count = align_up(size, PAGE_SIZE) >> PAGE_SHIFT;
        RawAllocMapping {
            pages: Vec::new(),
            count,
        }
    }

    /// Allocates the backing pages of type PageFile
    ///
    /// # Returns
    ///
    /// `Ok(())` when all pages could be allocated, `Err(SvsmError::Mem)` otherwise
    pub fn alloc_pages(&mut self) -> Result<(), SvsmError> {
        for _ in 0..self.count {
            self.pages.push(allocate_file_page_ref()?);
        }

        Ok(())
    }

    /// Request size of the mapping in bytes
    ///
    /// # Returns
    ///
    /// The size of the mapping in bytes as `usize`.
    pub fn mapping_size(&self) -> usize {
        self.count * PAGE_SIZE
    }

    /// Request physical address to map for a given offset
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset into the memory mapping
    ///
    /// # Returns
    ///
    /// Physical address to map for the given offset.
    pub fn map(&self, offset: usize) -> Option<PhysAddr> {
        let pfn = offset >> PAGE_SHIFT;
        self.pages.get(pfn).map(|r| r.phys_addr())
    }

    /// Unmap call-back - currently nothing to do in this function
    ///
    /// # Arguments
    ///
    /// * `_offset` - Byte offset into the mapping
    pub fn unmap(&self, _offset: usize) {
        // Nothing to do for now
    }
}
