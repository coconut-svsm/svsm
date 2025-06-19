// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::VirtualMapping;
use crate::address::{PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::mm::address_space::STACK_SIZE;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::PageRef;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::utils::{page_align_up, MemoryRegion};

use super::rawalloc::RawAllocMapping;
use super::Mapping;

/// Mapping to be used as a kernel stack. This maps a stack including guard
/// pages at the top and bottom.
#[derive(Default, Debug)]
pub struct VMKernelStack {
    /// Allocation for stack pages
    alloc: RawAllocMapping,
    /// Number of guard pages to reserve address space for
    guard_pages: usize,
    /// `True` for shadow stacks
    shadow: bool,
}

impl VMKernelStack {
    /// Returns the virtual address for the top of this kernel stack
    ///
    /// # Arguments
    ///
    /// * `base` - Virtual base address this stack is mapped at (including
    ///   guard pages).
    ///
    /// # Returns
    ///
    /// Offset from start of virtual mapping to top-of-stack.
    pub fn top_of_stack(&self) -> usize {
        let guard_size = self.guard_pages * PAGE_SIZE;
        let tos = guard_size + self.alloc.mapping_size();
        debug_assert!(tos > guard_size);
        tos
    }

    /// Returns the stack bounds of this kernel stack
    ///
    /// # Arguments
    ///
    /// * `base` - Virtual base address this stack is mapped at (including
    ///   guard pages).
    ///
    /// # Returns
    ///
    /// A [`MemoryRegion`] object containing the bottom and top addresses for
    /// the stack
    pub fn bounds(&self, base: VirtAddr) -> MemoryRegion<VirtAddr> {
        let mapping_size = self.alloc.mapping_size();
        let guard_size = self.guard_pages * PAGE_SIZE;
        MemoryRegion::new(base + guard_size, mapping_size)
    }

    /// Create a new [`VMKernelStack`] with a given size. This function will
    /// already allocate the backing pages for the stack.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the kernel stack, without guard pages
    /// * `shadow` - Whether this mapping is for a shadow stack
    ///
    /// # Returns
    ///
    /// Initialized stack on success, Err(SvsmError::Mem) on error
    fn new_size(size: usize, shadow: bool) -> Result<Self, SvsmError> {
        // Make sure size is page-aligned
        let size = page_align_up(size);
        // At least two guard-pages needed
        let total_size = (size + 2 * PAGE_SIZE).next_power_of_two();
        let guard_pages = ((total_size - size) >> PAGE_SHIFT) / 2;
        let mut stack = VMKernelStack {
            alloc: RawAllocMapping::new(size),
            guard_pages,
            shadow,
        };
        stack.alloc_pages()?;

        Ok(stack)
    }

    /// Create a new [`VMKernelStack`] with the default size. This function
    /// will already allocate the backing pages for the stack.
    ///
    /// # Returns
    ///
    /// Initialized stack on success, Err(SvsmError::Mem) on error
    pub fn new() -> Result<Self, SvsmError> {
        VMKernelStack::new_size(STACK_SIZE, false)
    }

    /// Create a new [`VMKernelStack`] with one page in size for use as a
    /// shadow stack.
    ///
    /// # Returns
    ///
    /// Shadow stack on success, Err(SvsmError::Mem) on error
    pub fn new_shadow() -> Result<Self, SvsmError> {
        VMKernelStack::new_size(PAGE_SIZE, true)
    }

    /// Get a reference to the shadow stack page. This is required because
    /// shadow stacks are mapped read-only and a separate mapping needs to be
    /// created to initialize it.
    ///
    /// # Returns
    ///
    /// A [`PageRef`] reference to the shadow stack page
    ///
    /// # Panics
    ///
    /// The function panics if called on a non-shadow-stack object.
    pub fn shadow_page(&self) -> PageRef {
        assert!(self.shadow);
        self.alloc.page(0)
    }

    /// Create a new [`VMKernelStack`] with the default size, packed into a
    /// [`Mapping`]. This function will allocate the backing pages for the
    /// stack.
    ///
    /// # Returns
    ///
    /// Initialized Mapping to stack on success, Err(SvsmError::Mem) on error
    pub fn new_mapping() -> Result<Mapping, SvsmError> {
        Ok(Mapping::new(Self::new()?))
    }

    fn alloc_pages(&mut self) -> Result<(), SvsmError> {
        self.alloc.alloc_pages()
    }
}

impl VirtualMapping for VMKernelStack {
    fn mapping_size(&self) -> usize {
        self.alloc.mapping_size() + ((self.guard_pages * 2) << PAGE_SHIFT)
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        let pfn = offset >> PAGE_SHIFT;
        let guard_offset = self.guard_pages << PAGE_SHIFT;

        if pfn >= self.guard_pages {
            self.alloc.map(offset - guard_offset)
        } else {
            None
        }
    }

    fn unmap(&self, offset: usize) {
        let pfn = offset >> PAGE_SHIFT;

        if pfn >= self.guard_pages {
            self.alloc.unmap(pfn - self.guard_pages);
        }
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        if self.shadow {
            // The CPU requires shadow stacks to be dirty and not writable.
            PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
        } else {
            PTEntryFlags::WRITABLE | PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
        }
    }
}
