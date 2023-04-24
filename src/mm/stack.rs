// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::flush_tlb_global_sync;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_zeroed_page, free_page};
use crate::mm::pagetable::{get_init_pgtable_locked, PageTable, PageTableRef};
use crate::mm::{phys_to_virt, virt_to_phys};
use crate::mm::{
    STACK_PAGES, STACK_SIZE, STACK_TOTAL_SIZE, SVSM_SHARED_STACK_BASE, SVSM_SHARED_STACK_END,
};
use crate::types::PAGE_SIZE;
use crate::utils::ffs;

// Limit maximum number of stacks for now, address range support 2**16 8k stacks
const MAX_STACKS: usize = 1024;
const BMP_QWORDS: usize = MAX_STACKS / 64;

struct StackRange {
    start: VirtAddr,
    end: VirtAddr,
    alloc_bitmap: [u64; BMP_QWORDS],
}

impl StackRange {
    pub const fn new(start: VirtAddr, end: VirtAddr) -> Self {
        StackRange {
            start,
            end,
            alloc_bitmap: [0; BMP_QWORDS],
        }
    }

    pub fn alloc(&mut self) -> Result<VirtAddr, SvsmError> {
        for i in 0..BMP_QWORDS {
            let val = !self.alloc_bitmap[i];
            let idx = ffs(val);

            if idx >= 64 {
                continue;
            }

            let mask = 1u64 << idx;

            self.alloc_bitmap[i] |= mask;

            return Ok(self.start.offset((i * 64 + idx) * STACK_TOTAL_SIZE));
        }

        Err(SvsmError::Mem)
    }

    pub fn dealloc(&mut self, stack: VirtAddr) {
        assert!(stack >= self.start && stack < self.end);

        let offset = stack - self.start;
        let idx = offset / (STACK_TOTAL_SIZE);

        assert!((offset % (STACK_TOTAL_SIZE)) <= STACK_SIZE);
        assert!(idx < MAX_STACKS);

        let i = idx / 64;
        let bit = idx % 64;
        let mask = 1u64 << bit;

        assert_eq!((self.alloc_bitmap[i] & mask), mask);

        self.alloc_bitmap[i] &= !mask;
    }
}

static STACK_ALLOC: SpinLock<StackRange> = SpinLock::new(StackRange::new(
    VirtAddr::new(SVSM_SHARED_STACK_BASE),
    VirtAddr::new(SVSM_SHARED_STACK_END),
));

pub fn allocate_stack_addr(stack: VirtAddr, pgtable: &mut PageTableRef) -> Result<(), SvsmError> {
    let flags = PageTable::data_flags();
    for i in 0..STACK_PAGES {
        let page = allocate_zeroed_page()?;
        let paddr = virt_to_phys(page);
        pgtable.map_4k(stack.offset(i * PAGE_SIZE), paddr, flags)?;
    }

    Ok(())
}

pub fn allocate_stack() -> Result<VirtAddr, SvsmError> {
    let stack = STACK_ALLOC.lock().alloc()?;
    allocate_stack_addr(stack, &mut get_init_pgtable_locked())?;
    Ok(stack)
}

pub fn stack_base_pointer(stack: VirtAddr) -> VirtAddr {
    VirtAddr::from((stack.bits() & !(STACK_SIZE - 1)) + STACK_SIZE)
}

pub fn free_stack(stack: VirtAddr) {
    let mut pages: [VirtAddr; STACK_PAGES] = [VirtAddr::null(); STACK_PAGES];

    let mut pgtable = get_init_pgtable_locked();
    for (i, page) in pages.iter_mut().enumerate() {
        let addr = stack.offset(i * PAGE_SIZE);
        let paddr = pgtable
            .phys_addr(addr)
            .expect("Failed to get stack physical address");
        let vaddr = phys_to_virt(paddr);
        pgtable.unmap_4k(addr);
        *page = vaddr;
    }

    // Pages are unmapped - flush TLB
    flush_tlb_global_sync();

    // Now free the stack pages
    for page in pages {
        free_page(page);
    }

    STACK_ALLOC.lock().dealloc(stack);
}
