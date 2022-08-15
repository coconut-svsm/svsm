// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PhysAddr};
use crate::mm::pagetable::PageTable;
use crate::locking::SpinLock;
use crate::mm;
use core::ptr;

pub fn allocate_pt_page() -> *mut u8 {
    let pt_page : VirtAddr = mm::alloc::allocate_zeroed_page().expect("Failed to allocate pgtable page");

    pt_page as *mut u8
}

pub fn virt_to_phys(vaddr : VirtAddr) -> PhysAddr {
    mm::alloc::virt_to_phys(vaddr)
}

pub fn phys_to_virt(paddr : PhysAddr) -> VirtAddr {
    mm::alloc::phys_to_virt(paddr)
}

pub fn map_page_shared(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).set_shared_4k(vaddr)
    }
}

pub fn map_page_encrypted(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).set_encrypted_4k(vaddr)
    }
}

pub fn map_data_4k(vaddr : VirtAddr, paddr : PhysAddr) -> Result<(), ()> {
    unsafe {
        let ptr   = INIT_PGTABLE.lock().as_mut().unwrap();
        let flags = PageTable::data_flags();
        (*ptr).map_4k(vaddr, paddr, &flags)
    }
}

pub fn unmap_4k(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).unmap_4k(vaddr)
    }
}

pub fn walk_addr(vaddr : VirtAddr) -> Result<PhysAddr, ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).phys_addr(vaddr)
    }
}

pub static INIT_PGTABLE : SpinLock<*mut PageTable> = SpinLock::new(ptr::null_mut());
