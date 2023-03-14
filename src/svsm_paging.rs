// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::heap_start;
use svsm::cpu::percpu::this_cpu_mut;
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm;
use svsm::mm::pagetable::{set_init_pgtable, PageTable, PageTableRef};
use svsm::mm::PerCPUPageMappingGuard;
use svsm::sev::ghcb::PageStateChangeOp;
use svsm::sev::pvalidate;
use svsm::types::{PhysAddr, VirtAddr, PAGE_SIZE};

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
    let offset =
        (launch_info.kernel_region_virt_start - launch_info.kernel_region_phys_start) as usize;

    let mut pgtable = PageTableRef::new(unsafe { &mut *(vaddr as *mut PageTable) });

    /* Text segment */
    let start: VirtAddr = (unsafe { &stext } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &etext } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable
        .map_region(start, end, phys, PageTable::exec_flags())
        .expect("Failed to map text segment");

    /* Writeble data */
    let start: VirtAddr = (unsafe { &sdata } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &edata } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable
        .map_region(start, end, phys, PageTable::data_flags())
        .expect("Failed to map data segment");

    /* Read-only data */
    let start: VirtAddr = (unsafe { &sdataro } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &edataro } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable
        .map_region(start, end, phys, PageTable::data_ro_flags())
        .expect("Failed to map read-only data");

    /* BSS */
    let start: VirtAddr = (unsafe { &sbss } as *const u8) as VirtAddr;
    let end: VirtAddr = (unsafe { &ebss } as *const u8) as VirtAddr;
    let phys: PhysAddr = start - offset;
    pgtable
        .map_region(start, end, phys, PageTable::data_flags())
        .expect("Failed to map bss segment");

    /* Heap */
    let start: VirtAddr = (unsafe { &heap_start } as *const u8) as VirtAddr;
    let end: VirtAddr = (launch_info.kernel_region_phys_end as VirtAddr) + offset;
    let phys: PhysAddr = start - offset;
    pgtable
        .map_region(start, end, phys, PageTable::data_flags())
        .expect("Failed to map heap");

    pgtable.load();

    set_init_pgtable(pgtable);
}

pub fn invalidate_stage2() -> Result<(), ()> {
    let pstart: PhysAddr = 0;
    let pend = pstart + (640 * 1024);
    let mut paddr = pstart;

    // Stage2 memory must be invalidated when already on the SVSM page-table,
    // because before that the stage2 page-table is still active, which is in
    // stage2 memory, causing invalidation of page-table pages.
    while paddr < pend {
        let guard = PerCPUPageMappingGuard::create(paddr, 0, false)?;
        let vaddr = guard.virt_addr();

        pvalidate(vaddr, false, false).expect("PINVALIDATE failed");

        paddr += PAGE_SIZE;
    }

    this_cpu_mut()
        .ghcb()
        .page_state_change(paddr, pend, false, PageStateChangeOp::PscShared)
        .expect("Failed to invalidate Stage2 memory");

    Ok(())
}
