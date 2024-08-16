// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_pages, get_order};
use crate::mm::virt_to_phys;
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;
use core::ptr;

static VALID_BITMAP: SpinLock<Option<ValidBitmap>> = SpinLock::new(None);

#[inline(always)]
fn bitmap_alloc_order(region: MemoryRegion<PhysAddr>) -> usize {
    let mem_size = region.len() / (PAGE_SIZE * 8);
    get_order(mem_size)
}

pub fn init_valid_bitmap_ptr(region: MemoryRegion<PhysAddr>, bitmap: *mut u64) {
    let bitmap = ValidBitmap::new(region, bitmap);
    *VALID_BITMAP.lock() = Some(bitmap);
}

pub fn init_valid_bitmap_alloc(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let order: usize = bitmap_alloc_order(region);
    let bitmap_addr = allocate_pages(order)?.as_mut_ptr();

    let mut bitmap = ValidBitmap::new(region, bitmap_addr);
    bitmap.clear_all();
    *VALID_BITMAP.lock() = Some(bitmap);

    Ok(())
}

pub fn migrate_valid_bitmap() -> Result<(), SvsmError> {
    let order: usize = VALID_BITMAP.lock().as_ref().unwrap().alloc_order();
    let bitmap_addr = allocate_pages(order)?;

    // lock again here because allocator path also takes VALID_BITMAP.lock()
    VALID_BITMAP
        .lock()
        .as_mut()
        .unwrap()
        .migrate(bitmap_addr.as_mut_ptr());
    Ok(())
}

pub fn validated_phys_addr(paddr: PhysAddr) -> bool {
    VALID_BITMAP
        .lock()
        .as_ref()
        .map(|vb| vb.is_valid_4k(paddr))
        .unwrap_or(false)
}

pub fn valid_bitmap_set_valid_4k(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.set_valid_4k(paddr);
    }
}

pub fn valid_bitmap_clear_valid_4k(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.clear_valid_4k(paddr);
    }
}

pub fn valid_bitmap_set_valid_2m(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.set_valid_2m(paddr);
    }
}

pub fn valid_bitmap_clear_valid_2m(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.clear_valid_2m(paddr);
    }
}

pub fn valid_bitmap_set_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.set_valid_range(paddr_begin, paddr_end);
    }
}

pub fn valid_bitmap_clear_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.clear_valid_range(paddr_begin, paddr_end);
    }
}

pub fn valid_bitmap_addr() -> PhysAddr {
    VALID_BITMAP.lock().as_ref().unwrap().bitmap_addr()
}

pub fn valid_bitmap_valid_addr(paddr: PhysAddr) -> bool {
    VALID_BITMAP
        .lock()
        .as_ref()
        .map(|vb| vb.check_addr(paddr))
        .unwrap_or(false)
}

#[derive(Debug)]
struct ValidBitmap {
    region: MemoryRegion<PhysAddr>,
    bitmap: *mut u64,
}

impl ValidBitmap {
    const fn new(region: MemoryRegion<PhysAddr>, bitmap: *mut u64) -> Self {
        Self { region, bitmap }
    }

    fn check_addr(&self, paddr: PhysAddr) -> bool {
        self.region.contains(paddr)
    }

    fn bitmap_addr(&self) -> PhysAddr {
        virt_to_phys(VirtAddr::from(self.bitmap))
    }

    #[inline(always)]
    fn index(&self, paddr: PhysAddr) -> (usize, usize) {
        let page_offset = (paddr - self.region.start()) / PAGE_SIZE;
        let index = page_offset / 64;
        let bit = page_offset % 64;

        (index, bit)
    }

    fn clear_all(&mut self) {
        let len = self.bitmap_len();
        unsafe {
            ptr::write_bytes(self.bitmap, 0, len);
        }
    }

    fn alloc_order(&self) -> usize {
        bitmap_alloc_order(self.region)
    }

    /// The number of u64's in the bitmap
    fn bitmap_len(&self) -> usize {
        let num_pages = self.region.len() / PAGE_SIZE;
        num_pages.div_ceil(u64::BITS as usize)
    }

    fn migrate(&mut self, new_bitmap: *mut u64) {
        let count = self.bitmap_len();
        unsafe {
            ptr::copy_nonoverlapping(self.bitmap, new_bitmap, count);
        }
        self.bitmap = new_bitmap;
    }

    fn set_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_addr(paddr));

        unsafe {
            let mut val: u64 = ptr::read(self.bitmap.add(index));
            val |= 1u64 << bit;
            ptr::write(self.bitmap.add(index), val);
        }
    }

    fn clear_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_addr(paddr));

        unsafe {
            let mut val: u64 = ptr::read(self.bitmap.add(index));
            val &= !(1u64 << bit);
            ptr::write(self.bitmap.add(index), val);
        }
    }

    fn set_2m(&mut self, paddr: PhysAddr, val: u64) {
        const NR_INDEX: usize = PAGE_SIZE_2M / (PAGE_SIZE * 64);
        let (index, _) = self.index(paddr);

        assert!(paddr.is_aligned(PAGE_SIZE_2M));
        assert!(self.check_addr(paddr));

        for i in 0..NR_INDEX {
            unsafe {
                ptr::write(self.bitmap.add(index + i), val);
            }
        }
    }

    fn set_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, !0u64);
    }

    fn clear_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, 0u64);
    }

    fn modify_bitmap_word(&mut self, index: usize, mask: u64, new_val: u64) {
        let val = unsafe { ptr::read(self.bitmap.add(index)) };
        let val = (val & !mask) | (new_val & mask);
        unsafe { ptr::write(self.bitmap.add(index), val) };
    }

    fn set_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr, new_val: bool) {
        // All ones.
        let mask = !0u64;
        // All ones if val == true, zero otherwise.
        let new_val = 0u64.wrapping_sub(new_val as u64);

        let (index_head, bit_head_begin) = self.index(paddr_begin);
        let (index_tail, bit_tail_end) = self.index(paddr_end);
        if index_head != index_tail {
            let mask_head = mask >> bit_head_begin << bit_head_begin;
            self.modify_bitmap_word(index_head, mask_head, new_val);

            for index in (index_head + 1)..index_tail {
                unsafe { ptr::write(self.bitmap.add(index), new_val) };
            }

            if bit_tail_end != 0 {
                let mask_tail = mask << (64 - bit_tail_end) >> (64 - bit_tail_end);
                self.modify_bitmap_word(index_tail, mask_tail, new_val);
            }
        } else {
            let mask = mask >> bit_head_begin << bit_head_begin;
            let mask = mask << (64 - bit_tail_end) >> (64 - bit_tail_end);
            self.modify_bitmap_word(index_head, mask, new_val);
        }
    }

    fn set_valid_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr) {
        self.set_range(paddr_begin, paddr_end, true);
    }

    fn clear_valid_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr) {
        self.set_range(paddr_begin, paddr_end, false);
    }

    fn is_valid_4k(&self, paddr: PhysAddr) -> bool {
        let (index, bit) = self.index(paddr);

        assert!(self.check_addr(paddr));

        unsafe {
            let mask: u64 = 1u64 << bit;
            let val: u64 = ptr::read(self.bitmap.add(index));

            (val & mask) == mask
        }
    }
}

unsafe impl Send for ValidBitmap {}
