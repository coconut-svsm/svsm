// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::utils::{rmp_adjust, RMPFlags};
use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::mm::alloc::{allocate_pages, free_page};
use crate::platform::guest_cpu::GuestCpuState;
use crate::sev::status::SEVStatusFlags;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;

use cpuarch::vmsa::{VmsaEventInject, VmsaEventType, VMSA};

pub const VMPL_MAX: usize = 4;

pub fn allocate_new_vmsa(vmpl: RMPFlags) -> Result<VirtAddr, SvsmError> {
    assert!(vmpl.bits() < (VMPL_MAX as u64));

    // Make sure the VMSA page is not 2M aligned. Some hardware generations
    // can't handle this properly.
    let mut vmsa_page = allocate_pages(0)?;
    if vmsa_page.is_aligned(PAGE_SIZE_2M) {
        free_page(vmsa_page);
        vmsa_page = allocate_pages(1)?;
        if vmsa_page.is_aligned(PAGE_SIZE_2M) {
            vmsa_page = vmsa_page + PAGE_SIZE;
        }
    }

    zero_mem_region(vmsa_page, vmsa_page + PAGE_SIZE);

    if let Err(e) = rmp_adjust(vmsa_page, RMPFlags::VMSA | vmpl, PageSize::Regular) {
        free_page(vmsa_page);
        return Err(e);
    }
    Ok(vmsa_page)
}

pub fn free_vmsa(vaddr: VirtAddr) {
    rmp_adjust(vaddr, RMPFlags::RWX | RMPFlags::VMPL0, PageSize::Regular)
        .expect("Failed to free VMSA page");
    free_page(vaddr);
}

pub trait VMSAControl {
    fn enable(&mut self);
    fn disable(&mut self);
}

impl VMSAControl for VMSA {
    fn enable(&mut self) {
        self.efer |= 1u64 << 12;
    }

    fn disable(&mut self) {
        self.efer &= !(1u64 << 12);
    }
}

impl GuestCpuState for VMSA {
    fn get_tpr(&self) -> u8 {
        let vintr_ctrl = self.vintr_ctrl;

        // The VMSA holds a 4-bit TPR but this routine must return an 8-bit
        // TPR to maintain consistency with PPR.
        vintr_ctrl.v_tpr() << 4
    }

    fn set_tpr(&mut self, tpr: u8) {
        let mut vintr_ctrl = self.vintr_ctrl;
        vintr_ctrl.set_v_tpr(tpr >> 4)
    }

    fn queue_interrupt(&mut self, irq: u8) {
        // Schedule the interrupt vector for delivery as a virtual interrupt.
        let mut vintr_ctrl = self.vintr_ctrl;
        vintr_ctrl.set_v_intr_vector(irq);
        vintr_ctrl.set_v_intr_prio(irq >> 4);
        vintr_ctrl.set_v_ign_tpr(false);
        vintr_ctrl.set_v_irq(true);
        self.vintr_ctrl = vintr_ctrl;
    }

    fn try_deliver_interrupt_immediately(&mut self, irq: u8) -> bool {
        // Attempt to inject the interrupt immediately using event injection.
        // If the event injection field already contains a pending event, then
        // injection is not possible.
        let event_inj = self.event_inj;
        if event_inj.valid() {
            false
        } else {
            self.event_inj = VmsaEventInject::new()
                .with_vector(irq)
                .with_valid(true)
                .with_event_type(VmsaEventType::Interrupt);
            true
        }
    }

    fn in_intr_shadow(&self) -> bool {
        let vintr_ctrl = self.vintr_ctrl;
        vintr_ctrl.int_shadow()
    }

    fn interrupts_enabled(&self) -> bool {
        (self.rflags & 0x200) != 0
    }

    fn check_and_clear_pending_interrupt_event(&mut self) -> u8 {
        // Check to see whether the current event injection is for an
        // interrupt.  If so, clear the pending event..
        let event_inj = self.event_inj;
        if event_inj.valid() && event_inj.event_type() == VmsaEventType::Interrupt {
            self.event_inj = VmsaEventInject::new();
            event_inj.vector()
        } else {
            0
        }
    }

    fn check_and_clear_pending_virtual_interrupt(&mut self) -> u8 {
        // Check to see whether a virtual interrupt is queued for delivery.
        // If so, clear the virtual interrupt request.
        let mut vintr_ctrl = self.vintr_ctrl;
        if vintr_ctrl.v_irq() {
            vintr_ctrl.set_v_irq(false);
            self.vintr_ctrl = vintr_ctrl;
            vintr_ctrl.v_intr_vector()
        } else {
            0
        }
    }
    fn disable_alternate_injection(&mut self) {
        let mut sev_status = SEVStatusFlags::from_sev_features(self.sev_features);
        sev_status.remove(SEVStatusFlags::ALT_INJ);
        self.sev_features = sev_status.as_sev_features();
    }
}
