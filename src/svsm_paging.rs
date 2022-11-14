// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::heap_start;
use crate::kernel_launch::KernelLaunchInfo;
use crate::mm;
use crate::mm::pagetable::{set_init_pgtable, get_init_pgtable_locked, PageTable, PageTableRef};
use crate::sev::msr_protocol::invalidate_page_msr;
use crate::sev::pvalidate;
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE};

extern "C" {
    static stext: u8;
    static etext: u8;
    static sdata: u8;
    static edata: u8;
    static sdataro: u8;
    static edataro: u8;
    static sbss: u8;
    static ebss: u8;
}

pub fn init_page_table(launch_info: &KernelLaunchInfo) {
    let vaddr = mm::alloc::allocate_zeroed_page().expect("Failed to allocate root page-table");
    let offset = (launch_info.virt_base - launch_info.kernel_start) as usize;

    let mut pgtable = PageTableRef::new(unsafe {&mut *(vaddr as *mut PageTable)});

    /* Text segment */
    let start: VirtAddr = (unsafe { &stext } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &etext } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable.map_region_4k(start, end, phys, PageTable::exec_flags()).expect("Failed to map text segment");

    /* Writeble data */
    let start: VirtAddr = (unsafe { &sdata } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &edata } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable.map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map data segment");

    /* Read-only data */
    let start: VirtAddr = (unsafe { &sdataro } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &edataro } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable.map_region_4k(start, end, phys, PageTable::data_ro_flags()).expect("Failed to map read-only data");

    /* BSS */
    let start: VirtAddr = (unsafe { &sbss } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &ebss } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable.map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map bss segment");

    /* Heap */
    let start: VirtAddr = (unsafe { &heap_start } as *const u8) as VirtAddr;
    let end: VirtAddr = (launch_info.kernel_end as VirtAddr) + offset;
    let phys: PhysAddr = start - offset;
    pgtable.map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map heap");

    pgtable.load();

    set_init_pgtable(pgtable);
}

pub fn invalidate_stage2() -> Result<(), ()> {
    let start: VirtAddr = 0;
    let end: VirtAddr = 640 * 1024;
    let phys: PhysAddr = 0;

    // Stage2 memory must be invalidated when already on the SVSM page-table,
    // because before that the stage2 page-table is still active, which is in
    // stage2 memory, causing invalidation of page-table pages.
    let mapping_guard = PTMappingGuard::create(start, end, phys);
    mapping_guard.check_mapping()?;

    let mut curr = start;
    loop {
        if curr >= end {
            break;
        }

        pvalidate(curr, false, false).expect("PINVALIDATE failed");

        let paddr = curr as PhysAddr;
        invalidate_page_msr(paddr)?;

        curr += PAGE_SIZE;
    }

    Ok(())
}

#[derive(Copy, Clone)]
pub struct RawPTMappingGuard {
    start: VirtAddr,
    end: VirtAddr,
}

impl RawPTMappingGuard {
    pub const fn new(start: VirtAddr, end: VirtAddr) -> Self {
        RawPTMappingGuard {
            start: start,
            end: end,
        }
    }
}

pub struct PTMappingGuard {
    mapping: Option<RawPTMappingGuard>,
}

impl PTMappingGuard {
    pub fn create(start: VirtAddr, end: VirtAddr, phys: PhysAddr) -> Self {
        let raw_mapping = RawPTMappingGuard::new(start, end);
        match get_init_pgtable_locked().map_region_4k(
                start,
                end,
                phys,
                PageTable::data_flags()) {
            Ok(()) => PTMappingGuard {
                mapping: Some(raw_mapping),
            },
            Err(()) => PTMappingGuard { mapping: None },
        }
    }

    pub fn check_mapping(&self) -> Result<(), ()> {
        match self.mapping {
            Some(_) => Ok(()),
            None => Err(()),
        }
    }
}

impl Drop for PTMappingGuard {
    fn drop(&mut self) {
        if let Some(m) = self.mapping {
            get_init_pgtable_locked().unmap_region_4k(m.start, m.end).expect("Failed guarded region");
        }
    }
}
