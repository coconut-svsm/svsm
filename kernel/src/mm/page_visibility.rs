// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::VirtAddr;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::mm::validate::{
    valid_bitmap_clear_valid_4k, valid_bitmap_set_valid_4k, valid_bitmap_valid_addr,
};
use crate::mm::virt_to_phys;
use crate::platform::{PageStateChangeOp, SVSM_PLATFORM};
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::MemoryRegion;

pub fn make_page_shared(vaddr: VirtAddr) -> Result<(), SvsmError> {
    let platform = SVSM_PLATFORM.as_dyn_ref();

    // Revoke page validation before changing page state.
    platform.invalidate_page_range(MemoryRegion::new(vaddr, PAGE_SIZE))?;
    let paddr = virt_to_phys(vaddr);
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_clear_valid_4k(paddr);
    }

    // Ask the hypervisor to make the page shared.
    platform.page_state_change(
        MemoryRegion::new(paddr, PAGE_SIZE),
        PageSize::Regular,
        PageStateChangeOp::Shared,
    )?;

    // Update the page tables to map the page as shared.
    this_cpu()
        .get_pgtable()
        .set_shared_4k(vaddr)
        .expect("Failed to remap shared page in page tables");
    flush_tlb_global_sync();

    Ok(())
}

pub fn make_page_private(vaddr: VirtAddr) -> Result<(), SvsmError> {
    // Update the page tables to map the page as private.
    this_cpu().get_pgtable().set_encrypted_4k(vaddr)?;
    flush_tlb_global_sync();

    let platform = SVSM_PLATFORM.as_dyn_ref();

    // Ask the hypervisor to make the page private.
    let paddr = virt_to_phys(vaddr);
    platform.page_state_change(
        MemoryRegion::new(paddr, PAGE_SIZE),
        PageSize::Regular,
        PageStateChangeOp::Private,
    )?;

    // Revoke page validation before changing page state.
    platform.validate_page_range(MemoryRegion::new(vaddr, PAGE_SIZE))?;
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_set_valid_4k(paddr);
    }

    Ok(())
}
