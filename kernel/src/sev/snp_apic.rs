// SPDX-License-Identifier: MIT
//
// Copyright (c) SUSE LLC
// Copyright (c) Microsoft Corporation
//
// Author: Joerg Roedel <jroedel@suse.de>
// Author: Jon Lange <jlange@microsoft.com>

use crate::cpu::percpu::current_ghcb;
use crate::cpu::x86::apic::{APIC_OFFSET_EOI, APIC_OFFSET_ICR};
use crate::cpu::x86::x2apic::MSR_X2APIC_BASE;
use crate::cpu::x86::{ApicAccess, MSR_APIC_BASE};
use crate::error::SvsmError;
use crate::sev::hv_doorbell::current_hv_doorbell;

use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub struct GHCBApicAccessor {
    use_restr_inj: AtomicBool,
}

impl GHCBApicAccessor {
    const fn new() -> Self {
        Self {
            use_restr_inj: AtomicBool::new(false),
        }
    }

    pub fn set_use_restr_inj(&self, use_restr_inj: bool) {
        self.use_restr_inj.store(use_restr_inj, Ordering::Relaxed)
    }

    pub fn use_restr_inj(&self) -> bool {
        self.use_restr_inj.load(Ordering::Relaxed)
    }
}

impl ApicAccess for GHCBApicAccessor {
    fn update_apic_base(&self, and_mask: u64, or_mask: u64) {
        let current_value = current_ghcb()
            .rdmsr(MSR_APIC_BASE)
            .expect("Failed to read MSR_APIC_BASE via GHCB call");
        let new_value = (current_value & and_mask) | or_mask;

        if current_value != new_value {
            current_ghcb()
                .wrmsr(MSR_APIC_BASE, new_value)
                .expect("Failed to write MSR_APIC_BASE via GHCB call");
        }
    }

    fn apic_write(&self, offset: usize, value: u64) {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        current_ghcb()
            .wrmsr(msr, value)
            .expect("Failed to write X2APIC MSR via GHCB call");
    }

    fn apic_read(&self, offset: usize) -> u64 {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        current_ghcb()
            .rdmsr(msr)
            .expect("Failed to read APIC MSR via GHCB call")
    }

    fn icr_write(&self, icr: u64) -> Result<(), SvsmError> {
        // HV_IPI (GHCB exit 0x0015) is a base SEV-ES protocol feature and
        // does not require restricted injection. KVM rejects direct WRMSR to
        // the x2APIC ICR MSR (0x830) via the GHCB MSR protocol (error 2),
        // so HV_IPI is the only reliable path.
        match current_ghcb().hv_ipi(icr) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Fallback: try direct MSR write if HV_IPI is unsupported
                self.apic_write(APIC_OFFSET_ICR, icr);
                Ok(())
            }
        }
    }

    fn eoi(&self) {
        // Issue an explicit EOI unless no explicit EOI is required.
        if !self.use_restr_inj() || !current_hv_doorbell().no_eoi_required() {
            self.apic_write(APIC_OFFSET_EOI, 0);
        }
    }
}

pub static GHCB_APIC_ACCESSOR: GHCBApicAccessor = GHCBApicAccessor::new();
