// SPDX-License-Identifier: MIT OR Apache-2.0 Copyright (c) Microsoft Corporation
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::ghcb::GHCBRef;
use crate::cpu::idt::svsm::common_isr_handler;
use crate::cpu::percpu::this_cpu_unsafe;
use crate::error::SvsmError;
use crate::mm::page_visibility::{make_page_private, make_page_shared};
use crate::mm::pagebox::PageBox;
use crate::mm::virt_to_phys;

use bitfield_struct::bitfield;
use core::ops::Deref;
use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug)]
pub struct HVDoorbellPage(PageBox<HVDoorbell>);

impl HVDoorbellPage {
    pub fn new(ghcb: GHCBRef) -> Result<Self, SvsmError> {
        let page = PageBox::try_new_zeroed()?;
        let vaddr = page.as_raw().vaddr();
        let paddr = virt_to_phys(vaddr);

        // The #HV doorbell page must be private before it can be used.
        make_page_shared(vaddr)?;
        // SAFETY: a zeroed `HVDoorbell` is valid
        let boxed = unsafe { Self(page.assume_init()) };

        // Register the #HV doorbell page using the GHCB protocol.
        ghcb.register_hv_doorbell(paddr)?;
        Ok(boxed)
    }
}

impl Deref for HVDoorbellPage {
    type Target = HVDoorbell;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl Drop for HVDoorbellPage {
    fn drop(&mut self) {
        let vaddr = self.0.as_raw().vaddr();
        make_page_private(vaddr).expect("Failed to restore HV doorbell page visibility");
    }
}

#[bitfield(u8)]
pub struct HVDoorbellFlags {
    pub nmi_pending: bool,
    pub mc_pending: bool,
    #[bits(5)]
    rsvd_6_2: u8,
    pub no_further_signal: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct HVDoorbell {
    pub vector: AtomicU8,
    pub flags: AtomicU8,
    pub no_eoi_required: AtomicU8,
    reserved: u8,
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

pub fn current_hv_doorbell() -> &'static HVDoorbell {
    let hv_doorbell = unsafe { (*this_cpu_unsafe()).hv_doorbell() };
    hv_doorbell.expect("HV doorbell page dereferenced before allocating")
}

/// # Safety
/// This function takes a raw pointer to the #HV doorbell page because it is
/// called directly from assembly, and should not be invoked directly from
/// Rust code.
#[no_mangle]
pub unsafe extern "C" fn process_hv_events(hv_doorbell: *const HVDoorbell) {
    unsafe {
        (*hv_doorbell).process_pending_events();
    }
}
