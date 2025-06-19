// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    address::PhysAddr,
    error::SvsmError,
    mm::{pagetable::PTEntryFlags, vm::VirtualMapping, PageRef, PAGE_SIZE},
};

/// Mapping to be used as a kernel stack. This maps a stack including guard
/// pages at the top and bottom.
#[derive(Debug)]
pub struct VMKernelShadowStack {
    page: PageRef,
}

impl VMKernelShadowStack {
    /// Create a new [`VMKernelShadowStack`].
    ///
    /// # Returns
    ///
    /// Initialized shadow stack & initial SSP value on success, Err(SvsmError::Mem) on error
    pub fn new() -> Result<Self, SvsmError> {
        let page = PageRef::new()?;

        Ok(VMKernelShadowStack { page })
    }

    pub fn top_of_stack_offet(&self) -> usize {
        PAGE_SIZE
    }

    pub fn page(&self) -> PageRef {
        self.page.clone()
    }
}

impl VirtualMapping for VMKernelShadowStack {
    fn mapping_size(&self) -> usize {
        PAGE_SIZE
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        assert_eq!(offset, 0);
        Some(self.page.phys_addr())
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        // The CPU requires shadow stacks to be dirty and not writable.
        PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }
}
