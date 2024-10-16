// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::VirtAddr;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::hyperv::HyperVMsr;
use crate::mm::alloc::allocate_pages;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::{virt_to_phys, SVSM_HYPERCALL_CODE_PAGE};
use crate::utils::immut_after_init::ImmutAfterInitCell;

static HYPERV_HYPERCALL_CODE_PAGE: ImmutAfterInitCell<VirtAddr> = ImmutAfterInitCell::uninit();

pub fn is_hyperv_hypervisor() -> bool {
    // Check if any hypervisor is present.
    if (CpuidResult::get(1, 0).ecx & 0x80000000) == 0 {
        return false;
    }

    // Get the hypervisor interface signature.
    CpuidResult::get(0x40000001, 0).eax == 0x31237648
}

pub fn hyperv_setup_hypercalls() -> Result<(), SvsmError> {
    // Allocate a page to use as the hypercall code page.
    let page = allocate_pages(1)?;

    // Map the page as executable at a known address.
    let hypercall_va = SVSM_HYPERCALL_CODE_PAGE;
    this_cpu()
        .get_pgtable()
        .map_4k(hypercall_va, virt_to_phys(page), PTEntryFlags::exec())?;

    HYPERV_HYPERCALL_CODE_PAGE
        .init(&hypercall_va)
        .expect("Hypercall code page already allocated");

    // Set the guest OS ID.  The value is arbitrary.
    write_msr(HyperVMsr::GuestOSID.into(), 0xC0C0C0C0);

    // Set the hypercall code page address to the physical address of the
    // allocated page, and mark it enabled.
    let pa = virt_to_phys(page);
    write_msr(HyperVMsr::Hypercall.into(), u64::from(pa) | 1);

    Ok(())
}
