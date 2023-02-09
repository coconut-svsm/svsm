// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{PAGE_SIZE, PAGE_SIZE_2M, PhysAddr};
use crate::utils::is_aligned;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_pages, get_order};
use core::ptr;

static VALID_BITMAP: SpinLock<ValidBitmap> = SpinLock::new(ValidBitmap::new());

pub fn init_valid_bitmap_ptr(pbase: PhysAddr, pend: PhysAddr, bitmap: *mut u64) {
    VALID_BITMAP.lock().set(pbase, pend, bitmap);
}

pub fn init_valid_bitmap_alloc(pbase: PhysAddr, pend: PhysAddr) -> Result<(), ()> {
    let mem_size = (pend - pbase) / (PAGE_SIZE * 8);
    let order = get_order(mem_size);
    let vaddr = allocate_pages(order)?;
    let bitmap = vaddr as *mut u64;

    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set(pbase, pend, bitmap);
    vb_ref.clear_all();

    Ok(())
}

pub fn migrate_valid_bitmap(new_bitmap: *mut u64) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.migrate(new_bitmap);
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

struct ValidBitmap {
    pbase: PhysAddr,
    pend: PhysAddr,
    bitmap: *mut u64,
}

impl ValidBitmap {
    pub const fn new() -> Self {
        ValidBitmap { pbase: 0, pend: 0, bitmap: ptr::null_mut() }
    }

    pub fn set(&mut self, pbase: PhysAddr, pend: PhysAddr, bitmap: *mut u64) {
        self.pbase = pbase;
        self.pend = pend;
        self.bitmap = bitmap;
    }

    pub fn check_addr(&self, paddr: PhysAddr) -> bool {
        paddr >= self.pbase && paddr < self.pend
    }

#[inline(always)]
    fn index(&self, paddr: PhysAddr) -> (isize, usize) {
        let page_offset = (paddr - self.pbase) / PAGE_SIZE;
        let index : isize = (page_offset / 64).try_into().unwrap();
        let bit: usize = page_offset % 64;

        (index, bit)
    }

    pub fn clear_all(&mut self) {
        let (i, _) = self.index(self.pend - 1);
        let index: usize = i.try_into().unwrap();

        unsafe { ptr::write_bytes(self.bitmap, 0, index); }
    }

    pub fn migrate(&mut self, new_bitmap: *mut u64) {
        let (count, _) = self.index(self.pend);

        unsafe {
            ptr::copy_nonoverlapping(self.bitmap, new_bitmap, count as usize);
        }
        self.bitmap = new_bitmap;
    }

    pub fn set_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(is_aligned(paddr, PAGE_SIZE));
        assert!(self.check_addr(paddr));

        unsafe {
            let mut val: u64 = ptr::read(self.bitmap.offset(index));
            val |= 1u64 << bit;
            ptr::write(self.bitmap.offset(index), val);
        }
    }

    pub fn clear_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(is_aligned(paddr, PAGE_SIZE));
        assert!(self.check_addr(paddr));

        unsafe {
            let mut val: u64 = ptr::read(self.bitmap.offset(index));
            val &= !(1u64 << bit);
            ptr::write(self.bitmap.offset(index), val);
        }
    }

    fn set_2m(&mut self, paddr: PhysAddr, val: u64) {
        const NR_INDEX: isize = (PAGE_SIZE_2M / (PAGE_SIZE * 64)) as isize;
        let (index, _) = self.index(paddr);

        assert!(is_aligned(paddr, PAGE_SIZE_2M));
        assert!(self.check_addr(paddr));

        for i in 0..NR_INDEX {
            unsafe { ptr::write(self.bitmap.offset(index + i), val); }
        }
    }

    pub fn set_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, !0u64);
    }

    pub fn clear_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, 0u64);
    }

    pub fn is_valid_4k(&self, paddr: PhysAddr) -> bool {
        let (index, bit) = self.index(paddr);

        assert!(self.check_addr(paddr));

        unsafe {
            let mask: u64 = 1u64 << bit;
            let val: u64 = ptr::read(self.bitmap.offset(index));
            
            (val & mask) == mask
        }
    }
}
