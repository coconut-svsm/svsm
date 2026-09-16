// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::mm::pagetable::PTEntryFlags;
use crate::types::PageSize;

extern crate alloc;
use alloc::sync::Arc;

/// Information required to resolve a page fault within a virtual mapping
#[derive(Debug, Copy, Clone)]
pub struct VMPageFaultResolution {
    /// The physical address of a page that must be mapped to the page fault
    /// virtual address to resolve the page fault.
    pub paddr: PhysAddr,

    /// The flags to use to map the virtual memory page.
    pub flags: PTEntryFlags,
}

pub trait VirtualMapping: core::fmt::Debug + Send + Sync {
    /// Request the size of the virtual memory mapping
    ///
    /// # Returns
    ///
    /// Mapping size. Will always be a multiple of `VirtualMapping::page_size()`
    fn mapping_size(&self) -> usize;

    /// Indicates whether the mapping has any associated data.
    ///
    /// # Returns
    ///
    /// `true' if there is associated physical data, or `false' if there is
    /// none.
    fn has_data(&self) -> bool {
        // Defaults to true
        true
    }

    /// Request physical address to map for a given offset
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset into the virtual memory mapping
    ///
    /// # Returns
    ///
    /// Physical address to map for the given offset, if any. None is also a
    /// valid return value and does not indicate an error.
    fn map(&self, offset: usize) -> Option<PhysAddr>;

    /// Inform the virtual memory mapping about an offset being unmapped.
    /// Implementing `unmap()` is optional.
    ///
    /// # Arguments
    ///
    /// * `_offset`
    fn unmap(&self, _offset: usize) {
        // Provide default in case there is nothing to do
    }

    /// Request the PTEntryFlags used for this virtual memory mapping.
    ///
    /// # Arguments
    ///
    /// * 'offset' -> The offset in bytes into the `VirtualMapping`. The flags
    ///   returned from this function relate to the page at the
    ///   given offset
    ///
    /// # Returns
    ///
    /// A combination of:
    ///
    /// * PTEntryFlags::WRITABLE
    /// * PTEntryFlags::NX,
    /// * PTEntryFlags::ACCESSED
    /// * PTEntryFlags::DIRTY
    fn pt_flags(&self, offset: usize) -> PTEntryFlags;

    /// Request the page size used for mappings
    ///
    /// # Returns
    ///
    /// Either PAGE_SIZE or PAGE_SIZE_2M
    fn page_size(&self) -> PageSize {
        // Default to system page-size
        PageSize::Regular
    }

    /// Request whether the mapping is shared or private. Defaults to private
    /// unless overwritten by the specific type.
    ///
    /// # Returns
    ///
    /// * `True` - When mapping is shared
    /// * `False` - When mapping is private
    fn shared(&self) -> bool {
        // Shared with the HV - defaults not No
        false
    }

    /// Handle a page fault that occurred on a virtual memory address within
    /// this mapping.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset into the virtual mapping that was the subject of
    ///   the page fault.
    ///
    /// * 'write' - `true` if the fault was due to a write to the memory
    ///   location, or 'false' if the fault was due to a read.
    fn handle_page_fault(
        &self,
        _offset: usize,
        _write: bool,
    ) -> Result<VMPageFaultResolution, SvsmError> {
        Err(SvsmError::Mem)
    }
}

pub type Mapping = Arc<dyn VirtualMapping>;
