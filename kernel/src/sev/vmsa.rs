// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::utils::{rmp_adjust, RMPFlags};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::mm::{virt_to_phys, PageBox};
use crate::platform::guest_cpu::GuestCpuState;
use crate::sev::status::SEVStatusFlags;
use crate::types::{PageSize, PAGE_SIZE_2M};
use core::mem::{size_of, ManuallyDrop};
use core::ops::{Deref, DerefMut};
use core::ptr;

use cpuarch::vmsa::{VmsaEventInject, VmsaEventType, VMSA};

pub const VMPL_MAX: usize = 4;

/// An allocated page containing a VMSA structure.
#[derive(Debug)]
pub struct VmsaPage {
    page: PageBox<[VMSA; 2]>,
    idx: usize,
}

impl VmsaPage {
    /// Allocates a new VMSA for the given VPML.
    pub fn new(vmpl: RMPFlags) -> Result<Self, SvsmError> {
        assert!(vmpl.bits() < (VMPL_MAX as u64));

        let page = PageBox::<[VMSA; 2]>::try_new_zeroed()?;
        // Make sure the VMSA page is not 2M-aligned, as some hardware
        // generations can't handle this properly. To ensure this property, we
        // allocate 2 VMSAs and choose whichever is not 2M-aligned.
        let idx = if page.vaddr().is_aligned(PAGE_SIZE_2M) {
            1
        } else {
            0
        };

        let vaddr = page.vaddr() + idx * size_of::<VMSA>();
        rmp_adjust(vaddr, RMPFlags::VMSA | vmpl, PageSize::Regular)?;
        Ok(Self { page, idx })
    }

    /// Returns the virtual address fro this VMSA.
    #[inline]
    fn vaddr(&self) -> VirtAddr {
        let ptr: *const VMSA = ptr::from_ref(&self.page[self.idx]);
        VirtAddr::from(ptr)
    }

    /// Returns the physical address for this VMSA.
    #[inline]
    pub fn paddr(&self) -> PhysAddr {
        virt_to_phys(self.vaddr())
    }

    /// Leaks the allocation for this VMSA, ensuring it never gets freed.
    pub fn leak(self) -> &'static mut VMSA {
        let mut vmsa = ManuallyDrop::new(self);
        // SAFETY: `self.idx` is either 0 or 1, so this will never overflow
        let ptr = unsafe { ptr::from_mut(&mut vmsa).add(vmsa.idx) };
        // SAFETY: this pointer will never be freed because of ManuallyDrop,
        // so we can create a static mutable reference. We go through a raw
        // pointer to promote the lifetime to static.
        unsafe { &mut *ptr }
    }
}

impl Drop for VmsaPage {
    fn drop(&mut self) {
        rmp_adjust(
            self.vaddr(),
            RMPFlags::RWX | RMPFlags::VMPL0,
            PageSize::Regular,
        )
        .expect("Failed to RMPADJUST VMSA page");
    }
}

impl Deref for VmsaPage {
    type Target = VMSA;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.page[self.idx]
    }
}

impl DerefMut for VmsaPage {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.page[self.idx]
    }
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

    fn request_nmi(&mut self) {
        self.event_inj = VmsaEventInject::new()
            .with_valid(true)
            .with_event_type(VmsaEventType::NMI);
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

    fn check_and_clear_pending_nmi(&mut self) -> bool {
        // Check to see whether the current event injection is for an
        // NMI.  If so, clear the pending event..
        let event_inj = self.event_inj;
        if event_inj.valid() && event_inj.event_type() == VmsaEventType::NMI {
            self.event_inj = VmsaEventInject::new();
            true
        } else {
            false
        }
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
