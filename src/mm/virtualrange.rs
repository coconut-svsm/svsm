// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use crate::types::{VirtAddr, PAGE_SHIFT, PAGE_SIZE, PAGE_SIZE_2M, PAGE_SHIFT_2M};
use crate::locking::SpinLock;
use crate::error::SvsmError;
use crate::utils::bitmap_allocator::{BitmapAllocator1024, BitmapAllocator};

use super::{SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_4K, SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_END_2M};

pub const VIRT_ALIGN_4K: usize = PAGE_SHIFT - 12;
pub const VIRT_ALIGN_2M: usize = PAGE_SHIFT_2M - 12;

pub struct VirtualRange {
    start_virt: VirtAddr,
    page_count: usize,
    bits: BitmapAllocator1024,
}

impl VirtualRange {
    pub const fn new() -> VirtualRange {
        VirtualRange {
            start_virt: 0,
            page_count: 0,
            bits: BitmapAllocator1024::new()
        }
    }

    pub fn map_pages(self: &mut Self, page_count: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
        // Always reserve an extra page to leave a guard between virtual memory allocations
        match self.bits.alloc(page_count + 1, alignment) {
            Some(offset) => Ok(self.start_virt + (offset << PAGE_SHIFT)),
            None => Err(SvsmError::Mem)
        }
    }

    pub fn unmap_pages(self: &mut Self, vaddr: VirtAddr, page_count: usize) {
        let offset = (vaddr - self.start_virt) >> PAGE_SHIFT;
        // Add 1 to the page count for the VM guard
        self.bits.free(offset, page_count + 1);
    }

    pub fn used_pages(&self) -> usize {
        self.bits.used()
    }
}

static VIRTUAL_MAP_4K: SpinLock<VirtualRange> = SpinLock::new(VirtualRange::new());
static VIRTUAL_MAP_2M: SpinLock<VirtualRange> = SpinLock::new(VirtualRange::new());

pub fn virt_range_init() {
    let mut pm4k = VIRTUAL_MAP_4K.lock();
    let page_count = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
    if page_count > BitmapAllocator1024::CAPACITY {
        panic!("Attempted to allocate page map with more than 4K pages");
    }
    pm4k.start_virt = SVSM_PERCPU_TEMP_BASE_4K;
    pm4k.page_count = page_count;
    pm4k.bits.set(0, page_count, false);

    let mut pm2m = VIRTUAL_MAP_2M.lock();
    let page_count = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
    if page_count > BitmapAllocator1024::CAPACITY {
        panic!("Attempted to allocate page map with more than 4K pages");
    }
    pm2m.start_virt = SVSM_PERCPU_TEMP_BASE_2M;
    pm2m.page_count = page_count;
    pm2m.bits.set(0, page_count, false);
}

pub fn virt_log_usage() {
    let page_count4k = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
    let page_count2m = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
    let unused_cap_4k = BitmapAllocator1024::CAPACITY - page_count4k;
    let unused_cap_2m = BitmapAllocator1024::CAPACITY - page_count2m;

    log::info!("Virtual memory pages used: {} * 4K, {} * 2M", 
        VIRTUAL_MAP_4K.lock().used_pages() - unused_cap_4k,
        VIRTUAL_MAP_2M.lock().used_pages() - unused_cap_2m);
}

pub fn virt_alloc_range_4k(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 4K page
    if (size_bytes & (PAGE_SIZE - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT;
    let mut pm = VIRTUAL_MAP_4K.lock();
    pm.map_pages(page_count, alignment)
}

pub fn virt_free_range_4k(vaddr: VirtAddr, size_bytes: usize) {
    VIRTUAL_MAP_4K.lock().unmap_pages(vaddr, size_bytes >> PAGE_SHIFT);
}

pub fn virt_alloc_range_2m(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 2M page
    if (size_bytes & (PAGE_SIZE_2M - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT_2M;
    let mut pm = VIRTUAL_MAP_2M.lock();
    pm.map_pages(page_count, alignment)
}

pub fn virt_free_range_2m(vaddr: VirtAddr, size_bytes: usize) {
    VIRTUAL_MAP_2M.lock().unmap_pages(vaddr, size_bytes >> PAGE_SHIFT_2M);
}
