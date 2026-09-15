// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::mm::pagetable::PTEntryFlags;

use super::rawalloc::RawAllocMapping;
use super::{Mapping, VirtualMapping};
use crate::mm::vm::VMFlags;

extern crate alloc;
use alloc::sync::Arc;

/// Virtual mapping backed by allocated pages. This can be used for memory
/// allocation if there is no need for the memory to be physically contiguous.
///
/// This is a wrapper around RawAllocMapping.
#[derive(Default, Debug)]
pub struct VMalloc {
    /// [`RawAllocMapping`] used for memory allocation
    alloc: RawAllocMapping,
    /// Page-table flags to map pages
    prot: PTEntryFlags,
}

impl VMalloc {
    /// Create a new instance and allocate backing memory
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the mapping. Must be aligned to PAGE_SIZE
    ///
    /// # Returns
    ///
    /// New instance on success, Err(SvsmError::Mem) on error
    pub fn new(size: usize, flags: VMFlags) -> Result<Self, SvsmError> {
        let mut vmalloc = VMalloc {
            alloc: RawAllocMapping::new(size),
            prot: flags.page_prot() | PTEntryFlags::ACCESSED,
        };

        if flags.contains(VMFlags::Write) {
            vmalloc.prot |= PTEntryFlags::DIRTY;
        }

        vmalloc.alloc_pages()?;
        Ok(vmalloc)
    }

    /// Create a new [`Mapping`] of [`VMalloc`] and allocate backing memory
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the mapping. Must be aligned to PAGE_SIZE
    ///
    /// # Returns
    ///
    /// New [`Mapping`] on success, Err(SvsmError::Mem) on error
    pub fn new_mapping(size: usize, flags: VMFlags) -> Result<Mapping, SvsmError> {
        Ok(Arc::new(Self::new(size, flags)?))
    }

    fn alloc_pages(&mut self) -> Result<(), SvsmError> {
        self.alloc.alloc_pages()
    }
}

impl VirtualMapping for VMalloc {
    fn mapping_size(&self) -> usize {
        self.alloc.mapping_size()
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        self.alloc.map(offset)
    }

    fn unmap(&self, offset: usize) {
        self.alloc.unmap(offset);
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        self.prot
    }

    fn split_at(&self, offset: usize) -> Result<(Mapping, Mapping), SvsmError> {
        let (head, tail) = self.alloc.split_at(offset)?;

        Ok((
            Arc::new(Self {
                alloc: head,
                prot: self.prot,
            }),
            Arc::new(Self {
                alloc: tail,
                prot: self.prot,
            }),
        ))
    }

    fn set_access(&self, access: VMFlags) -> Result<Mapping, SvsmError> {
        Ok(Arc::new(Self {
            alloc: self.alloc.try_clone()?,
            prot: self.prot.with_prot(access.page_prot()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::alloc::{DEFAULT_TEST_MEMORY_SIZE, TestRootMem};
    use crate::types::PAGE_SIZE;

    #[test]
    fn test_set_access() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

        let vm = VMalloc::new(4 * PAGE_SIZE, VMFlags::Write).expect("Failed to create VMalloc");
        assert!(vm.pt_flags(0).contains(PTEntryFlags::WRITABLE));

        let ro = vm.set_access(VMFlags::Read).expect("Failed to set access");
        assert!(!ro.pt_flags(0).contains(PTEntryFlags::WRITABLE));
        // The original is left untouched.
        assert!(vm.pt_flags(0).contains(PTEntryFlags::WRITABLE));

        // The access is set, not reduced, so it can be granted again.
        let rw = ro.set_access(VMFlags::Write).expect("Failed to set access");
        assert!(rw.pt_flags(0).contains(PTEntryFlags::WRITABLE));
    }

    #[test]
    fn test_split_at() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

        let vm = VMalloc::new(4 * PAGE_SIZE, VMFlags::Write).expect("Failed to create VMalloc");

        let (head, tail) = vm.split_at(PAGE_SIZE).expect("Failed to split");
        assert_eq!(head.mapping_size(), PAGE_SIZE);
        assert_eq!(tail.mapping_size(), 3 * PAGE_SIZE);

        // Splitting at an invalid offset is rejected.
        assert!(vm.split_at(0).is_err());
        assert!(vm.split_at(4 * PAGE_SIZE).is_err());
        assert!(vm.split_at(PAGE_SIZE / 2).is_err());
    }
}
