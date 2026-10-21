// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::iter;

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::mm::alloc::PageRef;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::utils::align_up;

extern crate alloc;
use alloc::vec::Vec;

/// Contains base functionality for all [`VirtualMapping`](super::api::VirtualMapping)
/// types which use self-allocated PageFile pages.
#[derive(Default, Debug)]
pub struct RawAllocMapping {
    /// A vec containing references to PageFile allocations
    pages: Vec<Option<PageRef>>,

    /// Number of pages required in `pages`
    count: usize,
}

impl RawAllocMapping {
    /// Clones the page references covering `range`, propagating allocation
    /// failure.
    ///
    /// # Returns
    ///
    /// The cloned page references, `Err(SvsmError::Mem)` if they could not be
    /// allocated.
    fn clone_pages<R>(&self, range: R) -> Result<Vec<Option<PageRef>>, SvsmError>
    where
        R: core::slice::SliceIndex<[Option<PageRef>], Output = [Option<PageRef>]>,
    {
        let src = &self.pages[range];
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(src.len())
            .map_err(|_| SvsmError::Mem)?;
        pages.extend_from_slice(src);
        Ok(pages)
    }

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
        let pages: Vec<Option<PageRef>> = iter::repeat_n(None, count).collect();
        RawAllocMapping { pages, count }
    }

    /// Splits the mapping in two at `offset`, returning the allocations
    /// covering `[0, offset)` and `[offset, mapping_size())`.
    ///
    /// The backing pages are shared with the new allocations.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in bytes to split at. Must be page-aligned and
    ///   strictly inside the mapping.
    ///
    /// # Returns
    ///
    /// The two new allocations on success, `Err(SvsmError::Mem)` if the offset
    /// is invalid or memory could not be allocated.
    pub fn split_at(&self, offset: usize) -> Result<(Self, Self), SvsmError> {
        let index = offset >> PAGE_SHIFT;
        if offset % PAGE_SIZE != 0 || index == 0 || index >= self.count {
            return Err(SvsmError::Mem);
        }

        Ok((
            Self {
                pages: self.clone_pages(..index)?,
                count: index,
            },
            Self {
                pages: self.clone_pages(index..)?,
                count: self.count - index,
            },
        ))
    }

    /// Returns a copy of this allocation, sharing its backing pages.
    ///
    /// # Returns
    ///
    /// The copy on success, `Err(SvsmError::Mem)` if memory could not be
    /// allocated.
    pub fn try_clone(&self) -> Result<Self, SvsmError> {
        Ok(Self {
            pages: self.clone_pages(..)?,
            count: self.count,
        })
    }

    /// Allocates a single backing page of type PageFile if the page has not already
    /// been allocated
    ///
    /// # Argument
    ///
    /// * 'offset' - The offset in bytes from the start of the mapping
    ///
    /// # Returns
    ///
    /// `Ok(())` if the page has been allocated, `Err(SvsmError::Mem)` otherwise
    pub fn alloc_page(&mut self, offset: usize) -> Result<(), SvsmError> {
        let index = offset >> PAGE_SHIFT;
        if index < self.count {
            let entry = self.pages.get_mut(index).ok_or(SvsmError::Mem)?;
            entry.get_or_insert(PageRef::new()?);
        }
        Ok(())
    }

    /// Allocates a full set of backing pages of type PageFile
    ///
    /// # Returns
    ///
    /// `Ok(())` when all pages could be allocated, `Err(SvsmError::Mem)` otherwise
    pub fn alloc_pages(&mut self) -> Result<(), SvsmError> {
        for index in 0..self.count {
            self.alloc_page(index * PAGE_SIZE)?;
        }
        Ok(())
    }

    /// Returns a reference to a page at a given index. The page must already
    /// been allocated.
    ///
    /// # Arguments
    ///
    /// * `index` - Page index to reference
    ///
    /// # Returns
    ///
    /// A reference to the requested page.
    ///
    /// # Panics
    ///
    /// This function panics if an invalid index is accessed or the page at the
    /// index has not been allocated.
    pub fn page(&self, index: usize) -> PageRef {
        self.pages[index].as_ref().unwrap().clone()
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
        self.pages
            .get(pfn)
            .and_then(|r| r.as_ref().map(|r| r.phys_addr()))
    }

    /// Unmap call-back - currently nothing to do in this function
    ///
    /// # Arguments
    ///
    /// * `_offset` - Byte offset into the mapping
    pub fn unmap(&self, _offset: usize) {
        // Nothing to do for now
    }

    /// Check if a page has been allocated
    ///
    /// # Arguments
    ///
    /// * 'offset' - Byte offset into the mapping
    ///
    /// # Returns
    ///
    /// 'true' if the page containing the offset has been allocated
    /// otherwise 'false'.
    pub fn present(&self, offset: usize) -> bool {
        let pfn = offset >> PAGE_SHIFT;
        self.pages.get(pfn).and_then(|r| r.as_ref()).is_some()
    }
}
