// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use super::page_visibility::{make_page_private, make_page_shared};
use super::pagetable::{make_private_address, PTEntryFlags, PTPage};
use super::{PerCPUMapping, PGTABLE_LVL3_IDX_SHARED};

use crate::address::PhysAddr;
use crate::config::SvsmConfig;
use crate::cpu::control_regs::read_cr3;
use crate::error::SvsmError;
use crate::types::{PAGE_SIZE, PAGE_SIZE_1G};

use bootlib::kernel_launch::SIPI_STUB_PT_GPA;

/// The `TransitionPageTable` structure represents a temporary set of page
/// tables to be used by secondary processors as they are started.  It
/// comprises the paging root that is used for SVSM kernel initialization
/// (which is not needed after the per-CPU page tables are created) and
/// it maps the low 4 GB of memory with an identity map, as well as the global
/// virtual address range.
#[derive(Debug)]
pub struct TransitionPageTable {
    // The page table page is not referenced after the page is allocated, but
    // it must contine to exist because it anchors a page allocation.
    change_page_state: bool,
    sipi_pt_mapping: [PerCPUMapping<PTPage>; 2],
}

impl TransitionPageTable {
    /// # Safety
    /// This must only be called during early boot when the SIPI stub page
    /// table is known not to be used for any other purpose.
    pub unsafe fn new(config: &SvsmConfig<'_>) -> Result<Self, SvsmError> {
        // Obtain a virtual address mapping the current page tables so they
        // can be examined.
        let current_pt_root =
            // SAFETY: the current paging root can always be safely mapepd for
            // reading.
            unsafe { PerCPUMapping::<PTPage>::create(make_private_address(read_cr3()))? };

        // Determine whether the SIPI stub page table pages have already been
        // validated.  If firmware is present in low memory, then the
        // pages have already been validated.
        let change_page_state = !config.fw_in_low_memory();

        // Map two pages to be used as initial page tables: one as a paging
        // root and one as the initial page directory page.
        let paging_root_paddr = PhysAddr::new(SIPI_STUB_PT_GPA as usize);
        let pdp_paddr = paging_root_paddr + PAGE_SIZE;
        let (mut paging_root, mut pdp_root) = if change_page_state {
            // The stub pages are currently shared, so map them as such.
            // SAFETY: these physical addresses are known to be usable for
            // transition page tables during early boot.
            unsafe {
                let paging_root = PerCPUMapping::<PTPage>::create_shared(paging_root_paddr)?;
                let pdp_root = PerCPUMapping::<PTPage>::create_shared(pdp_paddr)?;

                // Convert both pages into private pages so they can be used as
                // transition page tables in low memory.
                make_page_private(paging_root.virt_addr())?;
                make_page_private(pdp_root.virt_addr()).inspect_err(|_| {
                    // If the second conversion fails, then restore the first
                    // page.  Failure of that restoration cannot be handled
                    // gracefully.
                    make_page_shared(paging_root.virt_addr())
                        .expect("Failed to restore shared page");
                })?;
                (paging_root, pdp_root)
            }
        } else {
            // SAFETY: these physical addresses are known to be usable for
            // transition page tables during early boot.
            unsafe {
                (
                    PerCPUMapping::<PTPage>::create(paging_root_paddr)?,
                    PerCPUMapping::<PTPage>::create(pdp_paddr)?,
                )
            }
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
        paging_root.as_mut()[0].set(make_private_address(pdp_paddr), pd_flags);

        // Copy the kernel entry from the current page table into the stub
        // page table.
        paging_root.as_mut()[PGTABLE_LVL3_IDX_SHARED] =
            current_pt_root.as_ref()[PGTABLE_LVL3_IDX_SHARED];

        Ok(Self {
            change_page_state,
            sipi_pt_mapping: [paging_root, pdp_root],
        })
    }

    // The root page table address is always the SIPI page table stub.
    pub fn cr3_value(&self) -> u32 {
        SIPI_STUB_PT_GPA
    }
}

impl Drop for TransitionPageTable {
    fn drop(&mut self) {
        // Make the SIPI stub page table a shared page again if required..
        if self.change_page_state {
            // SAFETY: the page was made shared when the object was created,
            // and that must be undone when the object is dropped.
            unsafe {
                for page in &self.sipi_pt_mapping {
                    make_page_shared(page.virt_addr()).expect("page could not be made shared");
                }
            }
        }
    }
}
