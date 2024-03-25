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

/// Virtual mapping backed by allocated pages. This can be used for memory
/// allocation if there is no need for the memory to be physically contiguous.
///
/// This is a wrapper around RawAllocMapping.
#[derive(Default, Debug)]
pub struct VMalloc {
    /// [`RawAllocMapping`] used for memory allocation
    alloc: RawAllocMapping,
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
    pub fn new(size: usize) -> Result<Self, SvsmError> {
        let mut vmalloc = VMalloc {
            alloc: RawAllocMapping::new(size),
        };
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
    pub fn new_mapping(size: usize) -> Result<Mapping, SvsmError> {
        Mapping::new(Self::new(size)?)
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
        PTEntryFlags::WRITABLE | PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }
}
