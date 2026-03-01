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
use core::cmp::Ordering;

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

    /// Pages to flush
    unmapped_pages: Vec<Option<PageRef>>,
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
        let pages: Vec<Option<PageRef>> = iter::repeat_n(None, count).collect();
        let unmapped_pages: Vec<Option<PageRef>> = Vec::new();
        RawAllocMapping {
            pages,
            count,
            unmapped_pages,
        }
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

    /// Allocates backing pages for the mapping starting at a give offset
    ///
    /// # Arguments:
    ///
    /// * `offset` - Byte offset into the mapping to start allocating from
    ///
    /// # Returns
    ///
    /// `Ok(())` when all pages could be allocated, `Err(SvsmError::Mem)` otherwise
    fn alloc_pages_offset(&mut self, offset: usize) -> Result<(), SvsmError> {
        let start = offset / PAGE_SIZE;
        for index in start..self.count {
            self.alloc_page(index * PAGE_SIZE)?;
        }
        Ok(())
    }

    /// Allocates a full set of backing pages of type PageFile
    ///
    /// # Returns
    ///
    /// `Ok(())` when all pages could be allocated, `Err(SvsmError::Mem)` otherwise
    pub fn alloc_pages(&mut self) -> Result<(), SvsmError> {
        self.alloc_pages_offset(0)
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

    /// Change the size of the mapping. Note that the backing pages are not yet
    /// freed when the mapping is shrinked. To free the pages a separate call to
    /// the `flush()` method is required.
    ///
    /// # Arguments
    ///
    /// * `size` - The new size of the mapping. This will be rounded up to the
    ///   next PAGE_SIZE boundary.
    ///
    /// # Returns
    ///
    /// Returns `OK(new_aligned_size)` on success, `Err(SvsmError)` on failure.
    pub fn resize(&mut self, size: usize) -> Result<usize, SvsmError> {
        let size = align_up(size, PAGE_SIZE);
        let old_size = self.mapping_size();

        match size.cmp(&old_size) {
            Ordering::Equal => Ok(size),
            Ordering::Greater => {
                // Increase pages vector
                let diff_count = (size - old_size) / PAGE_SIZE;
                let new_total_count = size / PAGE_SIZE;
                // Reserve memory in pages vector
                self.pages
                    .try_reserve_exact(diff_count)
                    .map_err(|_| SvsmError::Mem)?;
                // Increase pages vector
                self.pages.resize_with(new_total_count, || None);
                self.count += diff_count;
                // Try to allocate the pages
                if let Err(e) = self.alloc_pages_offset(old_size) {
                    // Shrink pages vector
                    self.count -= diff_count;
                    // Free any stale backing pages
                    self.pages.truncate(self.count);
                    Err(e)
                } else {
                    Ok(size)
                }
            }
            Ordering::Less => {
                self.count = size / PAGE_SIZE;
                let mut old_pages = self.pages.split_off(self.count);
                self.unmapped_pages.append(&mut old_pages);
                Ok(size)
            }
        }
    }

    /// Free unmapped pages. This needs to be called after the unmapped pages
    /// have been flushed out of all TLBs.
    pub fn flush(&mut self) {
        self.unmapped_pages.clear();
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
