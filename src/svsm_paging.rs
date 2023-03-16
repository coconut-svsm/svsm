// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use svsm::cpu::percpu::this_cpu_mut;
use svsm::elf;
use svsm::error::SvsmError;
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm;
use svsm::mm::pagetable::{set_init_pgtable, PageTable, PageTableRef};
use svsm::mm::PerCPUPageMappingGuard;
use svsm::sev::ghcb::PageStateChangeOp;
use svsm::sev::pvalidate;
use svsm::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use svsm::utils::page_align_up;

pub fn init_page_table(launch_info: &KernelLaunchInfo, kernel_elf: &elf::Elf64File) {
    let vaddr = mm::alloc::allocate_zeroed_page().expect("Failed to allocate root page-table");
    let mut pgtable = PageTableRef::new(unsafe { &mut *(vaddr as *mut PageTable) });

    // Install mappings for the kernel's ELF segments each.
    // The memory backing the kernel ELF segments gets allocated back to back
    // from the physical memory region by the Stage2 loader.
    let mut phys = launch_info.kernel_region_phys_start as PhysAddr;
    for segment in kernel_elf.image_load_segment_iter(launch_info.kernel_region_virt_start) {
        let vaddr_start = segment.vaddr_range.vaddr_begin as VirtAddr;
        let vaddr_end = segment.vaddr_range.vaddr_end as VirtAddr;
        let aligned_vaddr_end = page_align_up(vaddr_end);
        let segment_len = aligned_vaddr_end - vaddr_start;
        let flags = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
            PageTable::exec_flags()
        } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
            PageTable::data_flags()
        } else {
            PageTable::data_ro_flags()
        };

        pgtable
            .map_region(vaddr_start, aligned_vaddr_end, phys, flags)
            .expect("Failed to map kernel ELF segment");

        phys += segment_len;
    }

    // Map subsequent heap area.
    pgtable
        .map_region(
            launch_info.heap_area_virt_start as VirtAddr,
            launch_info.heap_area_virt_end() as VirtAddr,
            launch_info.heap_area_phys_start as PhysAddr,
            PageTable::data_flags(),
        )
        .expect("Failed to map heap");

    pgtable.load();

    set_init_pgtable(pgtable);
}

pub fn invalidate_stage2() -> Result<(), SvsmError> {
    let pstart: PhysAddr = 0;
    let pend = pstart + (640 * 1024);
    let mut paddr = pstart;

    // Stage2 memory must be invalidated when already on the SVSM page-table,
    // because before that the stage2 page-table is still active, which is in
    // stage2 memory, causing invalidation of page-table pages.
    while paddr < pend {
        let guard = PerCPUPageMappingGuard::create(paddr, 0, false)?;
        let vaddr = guard.virt_addr();

        pvalidate(vaddr, false, false)?;

        paddr += PAGE_SIZE;
    }

    this_cpu_mut()
        .ghcb()
        .page_state_change(paddr, pend, false, PageStateChangeOp::PscShared)
        .expect("Failed to invalidate Stage2 memory");

    Ok(())
}
