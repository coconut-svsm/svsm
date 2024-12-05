// SPDX-License-Identifier: MIT OR Apache-2.0 Copyright (c) Microsoft Corporation
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::idt::svsm::common_isr_handler;
use crate::cpu::percpu::this_cpu;
use crate::cpu::IrqState;
use crate::error::SvsmError;
use crate::mm::page_visibility::SharedBox;
use crate::mm::virt_to_phys;
use crate::sev::ghcb::GHCB;

use bitfield_struct::bitfield;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

#[bitfield(u8)]
pub struct HVDoorbellFlags {
    pub nmi_pending: bool,
    pub mc_pending: bool,
    #[bits(5)]
    rsvd_6_2: u8,
    pub no_further_signal: bool,
}

#[bitfield(u32)]
pub struct HVExtIntStatus {
    pub pending_vector: u8,
    pub nmi_pending: bool,
    pub mc_pending: bool,
    pub level_sensitive: bool,
    #[bits(3)]
    rsvd_13_11: u32,
    pub multiple_vectors: bool,
    #[bits(12)]
    rsvd_26_15: u32,
    ipi_requested: bool,
    #[bits(3)]
    rsvd_30_28: u32,
    pub vector_31: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct HVExtIntInfo {
    pub status: AtomicU32,
    pub irr: [AtomicU32; 7],
    pub isr: [AtomicU32; 8],
}

/// Allocates a new HV doorbell page and registers it on the hypervisor
/// using the given GHCB.
pub fn allocate_hv_doorbell_page(ghcb: &GHCB) -> Result<&'static HVDoorbell, SvsmError> {
    let page = SharedBox::<HVDoorbell>::try_new_zeroed()?;

    let vaddr = page.addr();
    let paddr = virt_to_phys(vaddr);
    ghcb.register_hv_doorbell(paddr)?;

    // Create a static shared reference.
    let ptr = page.leak();
    let doorbell = unsafe {
        // SAFETY: Any bit-pattern is valid for `HVDoorbell` and it tolerates
        // unsynchronized writes from the host.
        ptr.as_ref()
    };

    Ok(doorbell)
}

#[repr(C)]
#[derive(Debug)]
pub struct HVDoorbell {
    pub vector: AtomicU8,
    pub flags: AtomicU8,
    pub no_eoi_required: AtomicU8,
    pub per_vmpl_events: AtomicU8,
    reserved_63_4: UnsafeCell<[u8; 60]>,
    pub per_vmpl: [HVExtIntInfo; 3],
}

impl HVDoorbell {
    pub fn process_pending_events(&self) {
        // Clear the NoFurtherSignal bit before processing.  If any additional
        // signal comes in after processing has commenced, it may be missed by
        // this loop, but it will be detected when interrupts are processed
        // again.  Also clear the NMI bit, since NMIs are not expected.
        let no_further_signal_mask: u8 = HVDoorbellFlags::new()
            .with_no_further_signal(true)
            .with_nmi_pending(true)
            .into();
        let flags = HVDoorbellFlags::from(
            self.flags
                .fetch_and(!no_further_signal_mask, Ordering::Relaxed),
        );

        // #MC handling is not possible, so panic if a machine check has
        // occurred.
        if flags.mc_pending() {
            panic!("#MC exception delivered via #HV");
        }

        // Consume interrupts as long as they are available.
        loop {
            // Consume any interrupt that may be present.
            let vector = self.vector.swap(0, Ordering::Relaxed);
            if vector == 0 {
                break;
            }
            common_isr_handler(vector as usize);
        }

        // Ignore per-VMPL events; these will be consumed when APIC emulation
        // is performed.
    }

    /// This function must always be called with interrupts enabled.
    pub fn process_if_required(&self, irq_state: &IrqState) {
        let flags = HVDoorbellFlags::from(self.flags.load(Ordering::Relaxed));
        while flags.no_further_signal() {
            // #HV event processing must always be performed with interrupts
            // disabled.
            irq_state.disable();
            self.process_pending_events();

            // Do not call the standard enable routine, because that could
            // recursively call to process new events, resulting in unbounded
            // nesting.  Intead, decrement the nesting count and directly
            // enable interrupts here before continuing the loop to see
            // whether additional events have arrived.
            assert_eq!(irq_state.pop_nesting(), 0);
            unsafe {
                asm!("sti");
            }
        }
    }

    pub fn no_eoi_required(&self) -> bool {
        // Check to see if the "no EOI required" flag is set to determine
        // whether an explicit EOI can be avoided.
        let mut no_eoi_required = self.no_eoi_required.load(Ordering::Relaxed);
        loop {
            // If the flag is not set, then an explicit EOI is required.
            if (no_eoi_required & 1) == 0 {
                return false;
            }
            // Attempt to atomically clear the flag.
            match self.no_eoi_required.compare_exchange_weak(
                no_eoi_required,
                no_eoi_required & !1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new) => no_eoi_required = new,
            }
        }

        // If the flag was successfully cleared, then no explicit EOI is
        // required.
        true
    }
}

/// Gets the HV doorbell page configured for this CPU.
///
/// # Panics
///
/// Panics if te HV doorbell page has not been set up beforehand.
pub fn current_hv_doorbell() -> &'static HVDoorbell {
    this_cpu()
        .hv_doorbell()
        .expect("HV doorbell page dereferenced before allocating")
}

/// # Safety
/// This function takes a raw pointer to the #HV doorbell page because it is
/// called directly from assembly, and should not be invoked directly from
/// Rust code.
#[no_mangle]
pub unsafe extern "C" fn process_hv_events(hv_doorbell: *const HVDoorbell) {
    // Update the IRQ nesting state of the current CPU so calls to common
    // code recognize that interrupts have been disabled.  Proceed as if
    // interrupts were previously enabled, so that any code that deals with
    // maskable interrupts knows that interrupts were enabled prior to reaching
    // this point.
    let cpu = this_cpu();
    cpu.irqs_push_nesting(true);
    unsafe {
        (*hv_doorbell).process_pending_events();
    }
    cpu.irqs_pop_nesting();
}
