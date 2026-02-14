// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use super::PGTABLE_LVL3_IDX_SHARED;
use super::PerCPUMapping;
use super::pagetable::PTEntryFlags;
use super::pagetable::PTPage;
use super::pagetable::make_private_address;

use crate::address::PhysAddr;
use crate::cpu::control_regs::read_cr3;
use crate::error::SvsmError;
use crate::types::PAGE_SIZE;
use crate::types::PAGE_SIZE_1G;

use bootdefs::kernel_launch::SIPI_STUB_PT_GPA;

/// The `TransitionPageTable` structure represents a temporary set of page
/// tables to be used by secondary processors as they are started.  It
/// comprises the paging root that is used for SVSM kernel initialization
/// (which is not needed after the per-CPU page tables are created) and
/// it maps the low 4 GB of memory with an identity map, as well as the global
/// virtual address range.
///
/// The transition page table object itself contains no data, but exists to
/// provide proof to the processor startup code that initialization was
/// completed successfully.
#[derive(Debug)]
pub struct TransitionPageTable {}

impl TransitionPageTable {
    /// # Safety
    /// This must only be called on platforms that do not require the use of
    /// a transition page table.
    pub unsafe fn empty() -> Self {
        Self {}
    }

    /// # Safety
    /// This must only be called during early boot when the SIPI stub page
    /// table is known not to be used for any other purpose.
    pub unsafe fn new() -> Result<Self, SvsmError> {
        // Obtain a virtual address mapping the current page tables so they
        // can be examined.
        let current_pt_root =
            // SAFETY: the current paging root can always be safely mapped for
            // reading.
            unsafe { PerCPUMapping::<PTPage>::create(make_private_address(read_cr3()))? };

        // Map two pages to be used as initial page tables: one as a paging
        // root and one as the initial page directory page.  These are known
        // to be usable because low memory has already been accepted.
        let paging_root_paddr = PhysAddr::new(SIPI_STUB_PT_GPA as usize);
        let pdp_paddr = paging_root_paddr + PAGE_SIZE;
        // SAFETY: these physical addresses are known to be usable for
        // transition page tables during early boot.
        let (mut paging_root, mut pdp_root) = unsafe {
            (
                PerCPUMapping::<PTPage>::create(paging_root_paddr)?,
                PerCPUMapping::<PTPage>::create(pdp_paddr)?,
            )
        };

        // No failures should be possible after this point because pages may
        // have changed state without a guard to restore the state upon
        // subsequent failure.  Note that the returned tracking object will
        // ensure that page state has been restored after the caller is done
        // with the page tables.

        // Fill in the first 4 GB using 1 GB entries.
        let pd_flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::ACCESSED
            | PTEntryFlags::DIRTY;
        let pt_flags = pd_flags | PTEntryFlags::HUGE;
        let mut paddr = make_private_address(PhysAddr::new(0));
        for index in 0..3 {
            pdp_root[index].set(paddr, pt_flags);
            paddr = paddr + PAGE_SIZE_1G;
        }

        // Set the first entry in the root page to point to the allocated
        // page table page.
        paging_root[0].set(make_private_address(pdp_paddr), pd_flags);

        // Copy the kernel entry from the current page table into the stub
        // page table.
        paging_root[PGTABLE_LVL3_IDX_SHARED] = current_pt_root[PGTABLE_LVL3_IDX_SHARED];

        Ok(Self {})
    }

    // The root page table address is always the SIPI page table stub.
    pub fn cr3_value(&self) -> u32 {
        SIPI_STUB_PT_GPA
    }
}
