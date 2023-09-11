// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use crate::address::VirtAddr;
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::error::SvsmError;
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator1024};
use core::fmt::Debug;

use super::{
    SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_2M,
    SVSM_PERCPU_TEMP_END_4K,
};

pub const VIRT_ALIGN_4K: usize = PAGE_SHIFT - 12;
pub const VIRT_ALIGN_2M: usize = PAGE_SHIFT_2M - 12;

#[derive(Debug, Default)]
pub struct VirtualRange {
    start_virt: VirtAddr,
    page_count: usize,
    page_shift: usize,
    bits: BitmapAllocator1024,
}

impl VirtualRange {
    pub const CAPACITY: usize = BitmapAllocator1024::CAPACITY;

    pub const fn new() -> VirtualRange {
        VirtualRange {
            start_virt: VirtAddr::null(),
            page_count: 0,
            page_shift: PAGE_SHIFT,
            bits: BitmapAllocator1024::new(),
        }
    }

    pub fn init(&mut self, start_virt: VirtAddr, page_count: usize, page_shift: usize) {
        self.start_virt = start_virt;
        self.page_count = page_count;
        self.page_shift = page_shift;
        self.bits.set(0, page_count, false);
    }

    pub fn alloc(&mut self, page_count: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
        // Always reserve an extra page to leave a guard between virtual memory allocations
        match self.bits.alloc(page_count + 1, alignment) {
            Some(offset) => Ok(self.start_virt + (offset << self.page_shift)),
            None => Err(SvsmError::Mem),
        }
    }

    pub fn free(&mut self, vaddr: VirtAddr, page_count: usize) {
        let offset = (vaddr - self.start_virt) >> self.page_shift;
        // Add 1 to the page count for the VM guard
        self.bits.free(offset, page_count + 1);
    }

    pub fn used_pages(&self) -> usize {
        self.bits.used()
    }
}

pub fn virt_log_usage() {
    let page_count4k = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
    let page_count2m = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
    let unused_cap_4k = BitmapAllocator1024::CAPACITY - page_count4k;
    let unused_cap_2m = BitmapAllocator1024::CAPACITY - page_count2m;

    log::info!(
        "[CPU {}] Virtual memory pages used: {} * 4K, {} * 2M",
        this_cpu().get_apic_id(),
        this_cpu().vrange_4k.used_pages() - unused_cap_4k,
        this_cpu().vrange_2m.used_pages() - unused_cap_2m
    );
}

pub fn virt_alloc_range_4k(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 4K page
    if (size_bytes & (PAGE_SIZE - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT;
    this_cpu_mut().vrange_4k.alloc(page_count, alignment)
}

pub fn virt_free_range_4k(vaddr: VirtAddr, size_bytes: usize) {
    this_cpu_mut()
        .vrange_4k
        .free(vaddr, size_bytes >> PAGE_SHIFT);
}

pub fn virt_alloc_range_2m(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 2M page
    if (size_bytes & (PAGE_SIZE_2M - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT_2M;
    this_cpu_mut().vrange_2m.alloc(page_count, alignment)
}

pub fn virt_free_range_2m(vaddr: VirtAddr, size_bytes: usize) {
    this_cpu_mut()
        .vrange_2m
        .free(vaddr, size_bytes >> PAGE_SHIFT_2M);
}

#[cfg(test)]
mod tests {
    use super::VirtualRange;
    use crate::address::VirtAddr;
    use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M};

    #[test]
    fn test_alloc_no_overlap_4k() {
        let mut range = VirtualRange::new();
        range.init(VirtAddr::new(0x1000000), 1024, PAGE_SHIFT);

        // Test that we get two virtual addresses that do
        // not overlap when using 4k pages.
        let v1 = range.alloc(12, 0);
        let v2 = range.alloc(12, 0);
        let v1 = u64::from(v1.unwrap());
        let v2 = u64::from(v2.unwrap());

        assert!(v1 < v2);
        assert!((v1 + (12 * PAGE_SIZE as u64)) < v2);
    }

    #[test]
    fn test_alloc_no_overlap_2m() {
        let mut range = VirtualRange::new();
        range.init(VirtAddr::new(0x1000000), 1024, PAGE_SHIFT_2M);

        // Test that we get two virtual addresses that do
        // not overlap when using 2M pages.
        let v1 = range.alloc(12, 0);
        let v2 = range.alloc(12, 0);
        let v1 = u64::from(v1.unwrap());
        let v2 = u64::from(v2.unwrap());

        assert!(v1 < v2);
        assert!((v1 + (12 * PAGE_SIZE_2M as u64)) < v2);
    }

    #[test]
    fn test_free_4k() {
        let mut range = VirtualRange::new();
        range.init(VirtAddr::new(0x1000000), 1024, PAGE_SHIFT);

        // This checks that freeing an allocated range giving the size
        // of the virtual region in bytes does indeed free the correct amount
        // of pages for 4K ranges.
        let v1 = range.alloc(26, 0).unwrap();
        // Page count will be 1 higher due to guard page.
        assert_eq!(range.used_pages(), 27);

        // If the page size calculation is wrong then there will be a mismatch between
        // the requested and freed page count.
        range.free(v1, 12);
        assert_eq!(range.used_pages(), 14);
        range.free(VirtAddr::new(u64::from(v1) as usize + (13 * PAGE_SIZE)), 13);
        assert_eq!(range.used_pages(), 0);
    }

    #[test]
    fn test_free_2m() {
        let mut range = VirtualRange::new();
        range.init(VirtAddr::new(0x1000000), 1024, PAGE_SHIFT_2M);

        // This checks that freeing an allocated range giving the size
        // of the virtual region in bytes does indeed free the correct amount
        // of pages for 4K ranges.
        let v1 = range.alloc(26, 0).unwrap();
        // Page count will be 1 higher due to guard page.
        assert_eq!(range.used_pages(), 27);

        // If the page size calculation is wrong then there will be a mismatch between
        // the requested and freed page count.
        range.free(v1, 12);
        assert_eq!(range.used_pages(), 14);
        range.free(
            VirtAddr::new(u64::from(v1) as usize + (13 * PAGE_SIZE_2M)),
            13,
        );
        assert_eq!(range.used_pages(), 0);
    }
}
