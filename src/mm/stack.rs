// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_zeroed_page, free_page};
use crate::mm::pagetable::flush_tlb_global;
use crate::types::{VirtAddr, PAGE_SIZE};
use crate::utils::ffs;
use crate::{map_data_4k, unmap_4k};
use crate::{phys_to_virt, virt_to_phys, walk_addr};

const STACK_RANGE_START: VirtAddr = 0xffff_ff80_4000_0000;
const STACK_RANGE_END: VirtAddr = 0xffff_ff80_8000_0000;

// Limit maximum number of stacks for now, address range support 2**16 8k stacks
const MAX_STACKS: usize = 1024;
const BMP_QWORDS: usize = MAX_STACKS / 64;

// Set stack size to 8k, certain macros can be very stack intensive (e.g. panic!)
const STACK_SIZE: usize = 2 * PAGE_SIZE;
const GUARD_SIZE: usize = 2 * PAGE_SIZE;
const STACK_PAGES: usize = STACK_SIZE / PAGE_SIZE;

struct StackRange {
    start: VirtAddr,
    end: VirtAddr,
    alloc_bitmap: [u64; BMP_QWORDS],
}

impl StackRange {
    pub const fn new(start: VirtAddr, end: VirtAddr) -> Self {
        StackRange {
            start: start,
            end: end,
            alloc_bitmap: [0; BMP_QWORDS],
        }
    }

    pub fn alloc(&mut self) -> Result<VirtAddr, ()> {
        for i in 0..BMP_QWORDS {
            let val = !self.alloc_bitmap[i];
            let idx = ffs(val);

            if idx >= 64 {
                continue;
            }

            let mask = 1u64 << idx;

            self.alloc_bitmap[i] |= mask;

            return Ok(self.start + (i * 64 + idx) * (STACK_SIZE + GUARD_SIZE));
        }

        Err(())
    }

    pub fn dealloc(&mut self, stack: VirtAddr) {
        assert!(stack >= self.start && stack < self.end);

        let offset = stack - self.start;
        let idx = offset / (STACK_SIZE + GUARD_SIZE);

        assert!((offset % (STACK_SIZE + GUARD_SIZE)) <= STACK_SIZE);
        assert!(idx < MAX_STACKS);

        let i = idx / 64;
        let bit = idx % 64;
        let mask = 1u64 << bit;

        assert!((self.alloc_bitmap[i] & mask) == mask);

        self.alloc_bitmap[i] &= !mask;
    }
}

static STACK_ALLOC: SpinLock<StackRange> =
    SpinLock::new(StackRange::new(STACK_RANGE_START, STACK_RANGE_END));

pub fn allocate_stack() -> Result<VirtAddr, ()> {
    let stack = STACK_ALLOC.lock().alloc()?;

    for i in 0..STACK_PAGES {
        let page = allocate_zeroed_page()?;
        let paddr = virt_to_phys(page);
        map_data_4k(stack + (i * PAGE_SIZE), paddr)?;
    }

    Ok(stack)
}

pub fn stack_base_pointer(stack: VirtAddr) -> VirtAddr {
    (stack & !(STACK_SIZE - 1)) + STACK_SIZE
}

pub fn free_stack(stack: VirtAddr) {
    let mut pages: [VirtAddr; STACK_PAGES] = [0; STACK_PAGES];

    for i in 0..STACK_PAGES {
        let addr = stack + (i * PAGE_SIZE);
        let paddr = walk_addr(addr).expect("Failed to get stack physical address");
        let vaddr = phys_to_virt(paddr);
        unmap_4k(addr).expect("Failed to unmap stack");
        pages[i] = vaddr;
    }

    // Pages are unmapped - flush TLB
    flush_tlb_global();

    // Now free the stack pages
    for i in 0..STACK_PAGES {
        free_page(pages[i]);
    }

    STACK_ALLOC.lock().dealloc(stack);
}
