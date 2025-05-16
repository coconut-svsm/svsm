// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::vm::VMR;
use crate::types::{PageSize, PAGE_SHIFT};

use intrusive_collections::rbtree::Link;
use intrusive_collections::{intrusive_adapter, KeyAdapter};

use core::ops::Range;

extern crate alloc;
use alloc::boxed::Box;
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

pub trait VirtualMapping: core::fmt::Debug {
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
    /// * 'vmr' - Virtual memory range that contains the mapping. This
    ///   [`VirtualMapping`] can use this to insert/remove regions
    ///   as necessary to handle the page fault.
    ///
    /// * `offset` - Offset into the virtual mapping that was the subject of
    ///   the page fault.
    ///
    /// * 'write' - `true` if the fault was due to a write to the memory
    ///   location, or 'false' if the fault was due to a read.
    fn handle_page_fault(
        &mut self,
        _vmr: &VMR,
        _offset: usize,
        _write: bool,
    ) -> Result<VMPageFaultResolution, SvsmError> {
        Err(SvsmError::Mem)
    }
}

#[derive(Debug)]
pub struct Mapping {
    mapping: RWLock<Box<dyn VirtualMapping>>,
}

unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    pub fn new<T>(mapping: T) -> Self
    where
        T: VirtualMapping + 'static,
    {
        Mapping {
            mapping: RWLock::new(Box::new(mapping)),
        }
    }

    pub fn get(&self) -> ReadLockGuard<'_, Box<dyn VirtualMapping>> {
        self.mapping.lock_read()
    }

    pub fn get_mut(&self) -> WriteLockGuard<'_, Box<dyn VirtualMapping>> {
        self.mapping.lock_write()
    }
}

/// A single mapping of virtual memory in a virtual memory range
#[derive(Debug)]
pub struct VMM {
    /// Link for storing this instance in an RBTree
    link: Link,

    /// The virtual memory range covered by this mapping
    /// It is stored in a RefCell to check borrowing rules at runtime.
    /// This is safe as any modification to `range` is protected by a lock in
    /// the parent data structure. This is required because changes here also
    /// need changes in the parent data structure.
    range: Range<usize>,

    /// Pointer to the actual mapping
    /// It is protected by an RWLock to serialize concurent accesses.
    mapping: Arc<Mapping>,
}

intrusive_adapter!(pub VMMAdapter = Box<VMM>: VMM { link: Link });

impl<'a> KeyAdapter<'a> for VMMAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a VMM) -> Self::Key {
        node.range.start
    }
}

impl VMM {
    /// Create a new VMM instance with at a given address and backing struct
    ///
    /// # Arguments
    ///
    /// * `start_pfn` - Virtual start pfn to store in the mapping
    /// * `mapping` - `Arc<Mapping>` pointer to the backing struct
    ///
    /// # Returns
    ///
    /// New instance of VMM
    pub fn new(start_pfn: usize, mapping: Arc<Mapping>) -> Self {
        let size = mapping.get().mapping_size() >> PAGE_SHIFT;
        VMM {
            link: Link::new(),
            range: Range {
                start: start_pfn,
                end: start_pfn + size,
            },
            mapping,
        }
    }

    /// Request the mapped range as page frame numbers
    ///
    /// # Returns
    ///
    /// The start and end (non-inclusive) virtual address for this virtual
    /// mapping, right-shifted by `PAGE_SHIFT`.
    pub fn range_pfn(&self) -> (usize, usize) {
        (self.range.start, self.range.end)
    }

    /// Request the mapped range
    ///
    /// # Returns
    ///
    /// The start and end virtual address for this virtual mapping.
    pub fn range(&self) -> (VirtAddr, VirtAddr) {
        (
            VirtAddr::from(self.range.start << PAGE_SHIFT),
            VirtAddr::from(self.range.end << PAGE_SHIFT),
        )
    }

    pub fn get_mapping(&self) -> ReadLockGuard<'_, Box<dyn VirtualMapping>> {
        self.mapping.get()
    }

    pub fn get_mapping_mut(&self) -> WriteLockGuard<'_, Box<dyn VirtualMapping>> {
        self.mapping.get_mut()
    }

    pub fn get_mapping_clone(&self) -> Arc<Mapping> {
        self.mapping.clone()
    }
}
