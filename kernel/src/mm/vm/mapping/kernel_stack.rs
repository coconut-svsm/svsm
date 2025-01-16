// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::VirtualMapping;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::mm::address_space::STACK_SIZE;
use crate::mm::pagetable::PTEntryFlags;
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
}

impl VMKernelStack {
    /// Returns the virtual address for the top of this kernel stack
    ///
    /// # Arguments
    ///
    /// * `base` - Virtual base address this stack is mapped at (including
    ///            guard pages).
    ///
    /// # Returns
    ///
    /// Virtual address to program into the hardware stack register
    pub fn top_of_stack(&self, base: VirtAddr) -> VirtAddr {
        let guard_size = self.guard_pages * PAGE_SIZE;
        let tos = (base + guard_size + self.alloc.mapping_size()).align_down(16);
        debug_assert!(tos > base + guard_size);
        tos
    }

    /// Returns the stack bounds of this kernel stack
    ///
    /// # Arguments
    ///
    /// * `base` - Virtual base address this stack is mapped at (including
    ///            guard pages).
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
    ///
    /// # Returns
    ///
    /// Initialized stack on success, Err(SvsmError::Mem) on error
    pub fn new_size(size: usize) -> Result<Self, SvsmError> {
        // Make sure size is page-aligned
        let size = page_align_up(size);
        // At least two guard-pages needed
        let total_size = (size + 2 * PAGE_SIZE).next_power_of_two();
        let guard_pages = ((total_size - size) >> PAGE_SHIFT) / 2;
        let mut stack = VMKernelStack {
            alloc: RawAllocMapping::new(size),
            guard_pages,
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
        VMKernelStack::new_size(STACK_SIZE)
    }

    /// Create a new [`VMKernelStack`] with the default size, packed into a
    /// [`Mapping`]. This function / will already allocate the backing pages for
    /// the stack.
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
        PTEntryFlags::WRITABLE | PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }
}
