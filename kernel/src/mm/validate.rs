// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr};
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::{virt_to_phys, PageBox};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;
use core::ptr::NonNull;

static VALID_BITMAP: SpinLock<Option<ValidBitmap>> = SpinLock::new(None);

fn bitmap_elems(region: MemoryRegion<PhysAddr>) -> NonZeroUsize {
    NonZeroUsize::new(
        region
            .len()
            .div_ceil(PAGE_SIZE)
            .div_ceil(u64::BITS as usize),
    )
    .unwrap()
}

/// # Safety
///
/// The caller must ensure that the given bitmap pointer is valid.
pub unsafe fn init_valid_bitmap_ptr(region: MemoryRegion<PhysAddr>, raw: NonNull<u64>) {
    let len = bitmap_elems(region);
    let ptr = NonNull::slice_from_raw_parts(raw, len.get());
    let bitmap = unsafe { PageBox::from_raw(ptr) };
    *VALID_BITMAP.lock() = Some(ValidBitmap::new(region, bitmap));
}

pub fn init_valid_bitmap_alloc(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let len = bitmap_elems(region);
    let bitmap = PageBox::try_new_slice(0u64, len)?;
    *VALID_BITMAP.lock() = Some(ValidBitmap::new(region, bitmap));

    Ok(())
}

pub fn migrate_valid_bitmap() -> Result<(), SvsmError> {
    let region = VALID_BITMAP.lock().as_ref().unwrap().region;
    let len = bitmap_elems(region);
    let bitmap = PageBox::try_new_uninit_slice(len)?;

    // lock again here because allocator path also takes VALID_BITMAP.lock()
    VALID_BITMAP.lock().as_mut().unwrap().migrate(bitmap);
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
    bitmap: PageBox<[u64]>,
}

impl ValidBitmap {
    const fn new(region: MemoryRegion<PhysAddr>, bitmap: PageBox<[u64]>) -> Self {
        Self { region, bitmap }
    }

    fn check_addr(&self, paddr: PhysAddr) -> bool {
        self.region.contains(paddr)
    }

    fn bitmap_addr(&self) -> PhysAddr {
        virt_to_phys(self.bitmap.vaddr())
    }

    #[inline(always)]
    fn index(&self, paddr: PhysAddr) -> (usize, usize) {
        let page_offset = (paddr - self.region.start()) / PAGE_SIZE;
        let index = page_offset / 64;
        let bit = page_offset % 64;

        (index, bit)
    }

    fn migrate(&mut self, mut new: PageBox<[MaybeUninit<u64>]>) {
        for (dst, src) in new
            .iter_mut()
            .zip(self.bitmap.iter().copied().chain(core::iter::repeat(0)))
        {
            dst.write(src);
        }
        // SAFETY: we initialized the contents of the whole slice
        self.bitmap = unsafe { new.assume_init_slice() };
    }

    fn set_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_addr(paddr));

        self.bitmap[index] |= 1u64 << bit;
    }

    fn clear_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_addr(paddr));

        self.bitmap[index] &= !(1u64 << bit);
    }

    fn set_2m(&mut self, paddr: PhysAddr, val: u64) {
        const NR_INDEX: usize = PAGE_SIZE_2M / (PAGE_SIZE * 64);
        let (index, _) = self.index(paddr);

        assert!(paddr.is_aligned(PAGE_SIZE_2M));
        assert!(self.check_addr(paddr));

        self.bitmap[index..index + NR_INDEX].fill(val);
    }

    fn set_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, !0u64);
    }

    fn clear_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, 0u64);
    }

    fn modify_bitmap_word(&mut self, index: usize, mask: u64, new_val: u64) {
        let val = &mut self.bitmap[index];
        *val = (*val & !mask) | (new_val & mask);
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

            self.bitmap[index_head + 1..index_tail].fill(new_val);

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

        let mask: u64 = 1u64 << bit;
        self.bitmap[index] & mask == mask
    }
}
