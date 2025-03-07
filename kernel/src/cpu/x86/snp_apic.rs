// SPDX-License-Identifier: MIT
//
// Copyright (c) SUSE LLC
// Copyright (c) Microsoft Corporation
//
// Author: Joerg Roedel <jroedel@suse.de>
// Author: Jon Lange <jlange@microsoft.com>

use super::apic::{ApicAccess, RawX86Apic, X86Apic};
use crate::cpu::percpu::current_ghcb;
use crate::sev::hv_doorbell::current_hv_doorbell;

#[derive(Debug)]
struct GHCBApicAccessor {}

const MSR_X2APIC_BASE: u32 = 0x800;

impl ApicAccess for GHCBApicAccessor {
    #[inline(always)]
    fn apic_write(offset: usize, value: u64) {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        current_ghcb()
            .wrmsr(msr, value)
            .expect("Failed to write X2APIC MSR via GHCB call");
    }

    #[inline(always)]
    fn apic_read(offset: usize) -> u64 {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        current_ghcb()
            .rdmsr(msr)
            .expect("Failed to read APIC MSR via GHCB call")
    }
}

type RawSnpApic = RawX86Apic<GHCBApicAccessor>;

#[derive(Debug)]
pub struct SnpGhcbApic {}

impl X86Apic for SnpGhcbApic {
    fn enable(&self) {
        // No enablement yet.
    }

    fn eoi(&self) {
        // Issue an explicit EOI unless no explicit EOI is required.
        if !current_hv_doorbell().no_eoi_required() {
            RawSnpApic::eoi();
        }
    }

    fn icr_write(&self, icr: u64) {
        current_ghcb()
            .hv_ipi(icr)
            .expect("Error sending HV_IPI via GHCB");
    }

    fn check_isr(&self, vector: usize) -> bool {
        RawSnpApic::check_isr(vector)
    }

    fn spiv_write(&self, vector: u8, enable: bool) {
        RawSnpApic::spiv_write(vector, enable);
    }

    fn sw_enable(&self) {
        RawSnpApic::sw_enable();
    }
}
