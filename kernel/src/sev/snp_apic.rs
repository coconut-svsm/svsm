// SPDX-License-Identifier: MIT
//
// Copyright (c) SUSE LLC
// Copyright (c) Microsoft Corporation
//
// Author: Joerg Roedel <jroedel@suse.de>
// Author: Jon Lange <jlange@microsoft.com>

use crate::cpu::percpu::current_ghcb;
use crate::cpu::x86::apic::APIC_OFFSET_EOI;
use crate::cpu::x86::x2apic::MSR_X2APIC_BASE;
use crate::cpu::x86::{ApicAccess, MSR_APIC_BASE};
use crate::error::SvsmError;
use crate::sev::hv_doorbell::current_hv_doorbell;

#[derive(Debug)]
pub struct GHCBApicAccessor {}

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
        current_ghcb().hv_ipi(icr)?;
        Ok(())
    }

    fn eoi(&self) {
        // Issue an explicit EOI unless no explicit EOI is required.
        if !current_hv_doorbell().no_eoi_required() {
            // 0x80B is the X2APIC EOI MSR.
            // Errors here cannot be handled but should not be grounds for
            // panic.
            self.apic_write(APIC_OFFSET_EOI, 0);
        }
    }
}

pub static GHCB_APIC_ACCESSOR: GHCBApicAccessor = GHCBApicAccessor {};
