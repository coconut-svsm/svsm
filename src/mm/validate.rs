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

static VALID_BITMAP: SpinLock<ValidBitmap> = SpinLock::new(ValidBitmap::new());

#[inline(always)]
fn bitmap_alloc_order(region: MemoryRegion<PhysAddr>) -> usize {
    let mem_size = region.len() / (PAGE_SIZE * 8);
    get_order(mem_size)
}

pub fn init_valid_bitmap_ptr(region: MemoryRegion<PhysAddr>, bitmap: *mut u64) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_region(region);
    vb_ref.set_bitmap(bitmap);
}

pub fn init_valid_bitmap_alloc(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let order: usize = bitmap_alloc_order(region);
    let bitmap_addr = allocate_pages(order)?;

    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_region(region);
    vb_ref.set_bitmap(bitmap_addr.as_mut_ptr::<u64>());
    vb_ref.clear_all();

    Ok(())
}

pub fn migrate_valid_bitmap() -> Result<(), SvsmError> {
    let order: usize = VALID_BITMAP.lock().alloc_order();
    let bitmap_addr = allocate_pages(order)?;

    // lock again here because allocator path also takes VALID_BITMAP.lock()
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.migrate(bitmap_addr.as_mut_ptr::<u64>());
    Ok(())
}

pub fn validated_phys_addr(paddr: PhysAddr) -> bool {
    let vb_ref = VALID_BITMAP.lock();
    vb_ref.is_valid_4k(paddr)
}

pub fn valid_bitmap_set_valid_4k(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_valid_4k(paddr)
}

pub fn valid_bitmap_clear_valid_4k(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.clear_valid_4k(paddr)
}

pub fn valid_bitmap_set_valid_2m(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_valid_2m(paddr)
}

pub fn valid_bitmap_clear_valid_2m(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.clear_valid_2m(paddr)
}

pub fn valid_bitmap_set_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_valid_range(paddr_begin, paddr_end);
}

pub fn valid_bitmap_clear_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.clear_valid_range(paddr_begin, paddr_end);
}

pub fn valid_bitmap_addr() -> PhysAddr {
    let vb_ref = VALID_BITMAP.lock();
    vb_ref.bitmap_addr()
}

pub fn valid_bitmap_valid_addr(paddr: PhysAddr) -> bool {
    let vb_ref = VALID_BITMAP.lock();
    vb_ref.check_addr(paddr)
}

#[derive(Debug)]
struct ValidBitmap {
    region: MemoryRegion<PhysAddr>,
    bitmap: *mut u64,
}

impl ValidBitmap {
    const fn new() -> Self {
        ValidBitmap {
            region: MemoryRegion::from_addresses(PhysAddr::null(), PhysAddr::null()),
            bitmap: ptr::null_mut(),
        }
    }

    fn set_region(&mut self, region: MemoryRegion<PhysAddr>) {
        self.region = region;
    }

    fn set_bitmap(&mut self, bitmap: *mut u64) {
        self.bitmap = bitmap;
    }

    fn check_addr(&self, paddr: PhysAddr) -> bool {
        self.region.contains(paddr)
    }

    fn bitmap_addr(&self) -> PhysAddr {
        assert!(!self.bitmap.is_null());
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
        let additional_u64 = if self.region.len() % PAGE_SIZE != 0 {
            1
        } else {
            0
        };
        num_pages + additional_u64
    }

    fn migrate(&mut self, new_bitmap: *mut u64) {
        let count = self.bitmap_len();
        unsafe {
            ptr::copy_nonoverlapping(self.bitmap, new_bitmap, count);
        }
        self.bitmap = new_bitmap;
    }

    fn initialized(&self) -> bool {
        !self.bitmap.is_null()
    }

    fn set_valid_4k(&mut self, paddr: PhysAddr) {
        if !self.initialized() {
            return;
        }

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
        if !self.initialized() {
            return;
        }

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
        if !self.initialized() {
            return;
        }

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
        if !self.initialized() {
            return;
        }

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
        if !self.initialized() {
            return false;
        }

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
