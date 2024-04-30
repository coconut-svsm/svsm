// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::VirtAddr;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::this_cpu_mut;
use crate::mm::validate::{
    valid_bitmap_clear_valid_4k, valid_bitmap_set_valid_4k, valid_bitmap_valid_addr,
};
use crate::mm::virt_to_phys;
use crate::platform::{PageStateChangeOp, SVSM_PLATFORM};
use crate::sev::PvalidateOp;
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::MemoryRegion;

pub fn make_page_shared(vaddr: VirtAddr) {
    let platform = SVSM_PLATFORM.as_dyn_ref();

    // Revoke page validation before changing page state.
    platform
        .pvalidate_range(MemoryRegion::new(vaddr, PAGE_SIZE), PvalidateOp::Invalid)
        .expect("Pvalidate failed when making page shared");
    let paddr = virt_to_phys(vaddr);
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_clear_valid_4k(paddr);
    }

    // Ask the hypervisor to make the page shared.
    platform
        .page_state_change(
            MemoryRegion::new(paddr, PAGE_SIZE),
            PageSize::Regular,
            PageStateChangeOp::Shared,
        )
        .expect("Hypervisor failed to make page shared");

    // Update the page tables to map the page as shared.
    this_cpu_mut()
        .get_pgtable()
        .set_shared_4k(vaddr)
        .expect("Failed to remap shared page in page tables");
    flush_tlb_global_sync();
}

pub fn make_page_private(vaddr: VirtAddr) {
    // Update the page tables to map the page as private.
    this_cpu_mut()
        .get_pgtable()
        .set_encrypted_4k(vaddr)
        .expect("Failed to remap private page in page tables");
    flush_tlb_global_sync();

    let platform = SVSM_PLATFORM.as_dyn_ref();

    // Ask the hypervisor to make the page private.
    let paddr = virt_to_phys(vaddr);
    platform
        .page_state_change(
            MemoryRegion::new(paddr, PAGE_SIZE),
            PageSize::Regular,
            PageStateChangeOp::Private,
        )
        .expect("Hypervisor failed to make page private");

    // Revoke page validation before changing page state.
    platform
        .pvalidate_range(MemoryRegion::new(vaddr, PAGE_SIZE), PvalidateOp::Valid)
        .expect("Pvalidate failed when making page private");
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_set_valid_4k(paddr);
    }
}
