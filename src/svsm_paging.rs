// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::heap_start;
use crate::kernel_launch::KernelLaunchInfo;
use crate::locking::SpinLock;
use crate::mm;
use crate::mm::pagetable::PageTable;
use crate::sev::msr_protocol::invalidate_page_msr;
use crate::sev::pvalidate;
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use core::ptr;

pub static INIT_PGTABLE: SpinLock<*mut PageTable> = SpinLock::new(ptr::null_mut());

pub fn allocate_pt_page() -> *mut u8 {
    let pt_page: VirtAddr =
        mm::alloc::allocate_zeroed_page().expect("Failed to allocate pgtable page");

    pt_page as *mut u8
}

pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    mm::alloc::virt_to_phys(vaddr)
}

pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    mm::alloc::phys_to_virt(paddr)
}

pub fn map_page_shared(vaddr: VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).set_shared_4k(vaddr)
    }
}

pub fn map_page_encrypted(vaddr: VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).set_encrypted_4k(vaddr)
    }
}

pub fn map_data_4k(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        let flags = PageTable::data_flags();
        (*ptr).map_4k(vaddr, paddr, &flags)
    }
}

pub fn unmap_4k(vaddr: VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).unmap_4k(vaddr)
    }
}

pub fn walk_addr(vaddr: VirtAddr) -> Result<PhysAddr, ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).phys_addr(vaddr)
    }
}

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
    let mut ptr = INIT_PGTABLE.lock();
    let offset = (launch_info.virt_base - launch_info.kernel_start) as usize;

    *ptr = vaddr as *mut PageTable;

    unsafe {
        let pgtable = ptr.as_mut().unwrap();

        /* Text segment */
        let start: VirtAddr = (&stext as *const u8) as VirtAddr;
        let end: VirtAddr = (&etext as *const u8) as VirtAddr;
        let phys: PhysAddr = start - offset;

        (*pgtable)
            .map_region_4k(start, end, phys, PageTable::exec_flags())
            .expect("Failed to map text segment");

        /* Writeble data */
        let start: VirtAddr = (&sdata as *const u8) as VirtAddr;
        let end: VirtAddr = (&edata as *const u8) as VirtAddr;
        let phys: PhysAddr = start - offset;

        (*pgtable)
            .map_region_4k(start, end, phys, PageTable::data_flags())
            .expect("Failed to map data segment");

        /* Read-only data */
        let start: VirtAddr = (&sdataro as *const u8) as VirtAddr;
        let end: VirtAddr = (&edataro as *const u8) as VirtAddr;
        let phys: PhysAddr = start - offset;

        (*pgtable)
            .map_region_4k(start, end, phys, PageTable::data_ro_flags())
            .expect("Failed to map read-only data");

        /* BSS */
        let start: VirtAddr = (&sbss as *const u8) as VirtAddr;
        let end: VirtAddr = (&ebss as *const u8) as VirtAddr;
        let phys: PhysAddr = start - offset;

        (*pgtable)
            .map_region_4k(start, end, phys, PageTable::data_flags())
            .expect("Failed to map bss segment");

        /* Heap */
        let start: VirtAddr = (&heap_start as *const u8) as VirtAddr;
        let end: VirtAddr = (launch_info.kernel_end as VirtAddr) + offset;
        let phys: PhysAddr = start - offset;

        (*pgtable)
            .map_region_4k(start, end, phys, PageTable::data_flags())
            .expect("Failed to map heap");

        (*pgtable).load();
    }
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
        unsafe {
            match INIT_PGTABLE.lock().as_mut().unwrap().map_region_4k(
                start,
                end,
                phys,
                PageTable::data_flags(),
            ) {
                Ok(()) => PTMappingGuard {
                    mapping: Some(raw_mapping),
                },
                Err(()) => PTMappingGuard { mapping: None },
            }
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
            unsafe {
                INIT_PGTABLE
                    .lock()
                    .as_mut()
                    .unwrap()
                    .unmap_region_4k(m.start, m.end)
                    .expect("Failed guarded region");
            }
        }
    }
}
