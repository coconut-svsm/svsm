// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr};
use crate::mm::{virt_to_phys, PageBox};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;

pub fn bitmap_elems(region: MemoryRegion<PhysAddr>) -> NonZeroUsize {
    NonZeroUsize::new(
        region
            .len()
            .div_ceil(PAGE_SIZE)
            .div_ceil(u64::BITS as usize),
    )
    .unwrap()
}

#[derive(Debug)]
pub struct ValidBitmap {
    region: MemoryRegion<PhysAddr>,
    bitmap: PageBox<[u64]>,
}

impl ValidBitmap {
    pub const fn new(region: MemoryRegion<PhysAddr>, bitmap: PageBox<[u64]>) -> Self {
        Self { region, bitmap }
    }
    
    pub fn region_len(&self) -> NonZeroUsize {
        return bitmap_elems(self.region);
    }

    pub fn check_addr(&self, paddr: PhysAddr) -> bool {
        self.region.contains(paddr)
    }

    pub fn bitmap_addr(&self) -> PhysAddr {
        virt_to_phys(self.bitmap.vaddr())
    }

    #[inline(always)]
    fn index(&self, paddr: PhysAddr) -> (usize, usize) {
        let page_offset = (paddr - self.region.start()) / PAGE_SIZE;
        let index = page_offset / 64;
        let bit = page_offset % 64;

        (index, bit)
    }

    pub fn migrate(&mut self, mut new: PageBox<[MaybeUninit<u64>]>) {
        for (dst, src) in new
            .iter_mut()
            .zip(self.bitmap.iter().copied().chain(core::iter::repeat(0)))
        {
            dst.write(src);
        }
        // SAFETY: we initialized the contents of the whole slice
        self.bitmap = unsafe { new.assume_init_slice() };
    }

    pub fn set_valid_4k(&mut self, paddr: PhysAddr) {
        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_addr(paddr));

        self.bitmap[index] |= 1u64 << bit;
    }

    pub fn clear_valid_4k(&mut self, paddr: PhysAddr) {
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

    pub fn set_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, !0u64);
    }

    pub fn clear_valid_2m(&mut self, paddr: PhysAddr) {
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

    pub fn set_valid_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr) {
        self.set_range(paddr_begin, paddr_end, true);
    }

    pub fn clear_valid_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr) {
        self.set_range(paddr_begin, paddr_end, false);
    }

    pub fn is_valid_4k(&self, paddr: PhysAddr) -> bool {
        let (index, bit) = self.index(paddr);

        assert!(self.check_addr(paddr));

        let mask: u64 = 1u64 << bit;
        self.bitmap[index] & mask == mask
    }
}
