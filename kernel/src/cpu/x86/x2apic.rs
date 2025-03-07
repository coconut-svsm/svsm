// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation
// Copyright (c) SUSE LLC
//
// Author: Jon Lange <jlange@microsoft.com>
// Author: Joerg Roedel <jroedel@suse.de>

use super::apic::{ApicAccess, RawX86Apic, X86Apic};
use crate::cpu::msr::{read_msr, write_msr};

const MSR_X2APIC_BASE: u32 = 0x800;

struct X2ApicAccessor {}

impl ApicAccess for X2ApicAccessor {
    #[inline(always)]
    fn apic_write(offset: usize, value: u64) {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        // SAFETY: Writes to X2APIC MSRs never harms memory safety.
        unsafe { write_msr(msr, value) };
    }

    #[inline(always)]
    fn apic_read(offset: usize) -> u64 {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        read_msr(msr)
    }
}

type RawX2Apic = RawX86Apic<X2ApicAccessor>;

#[derive(Debug, Default)]
pub struct X2Apic {
    // Skip enablement via MSR_APIC_BASE
    skip_msr_enable: bool,
}

impl X2Apic {
    /// Creates new instance of [`X2Apic`] which needs to be enabled via
    /// MSR_APIC_BASE.
    pub fn new() -> Self {
        Self {
            skip_msr_enable: false,
        }
    }

    /// Creates new instance of [`X2Apic`] which does not need to be enabled
    /// via MSR_APIC_BASE.
    pub fn new_skip_msr_enable() -> Self {
        Self {
            skip_msr_enable: true,
        }
    }
}

// APIC MSR
const MSR_APIC_BASE: u32 = 0x1B;
// APIC enable masks
const APIC_ENABLE_MASK: u64 = 0x800;
const APIC_X2_ENABLE_MASK: u64 = 0x400;

impl X86Apic for X2Apic {
    fn enable(&self) {
        // Enable X2APIC mode.
        if !self.skip_msr_enable {
            let apic_base = read_msr(MSR_APIC_BASE);
            let apic_base_x2_enabled = apic_base | APIC_ENABLE_MASK | APIC_X2_ENABLE_MASK;
            if apic_base != apic_base_x2_enabled {
                // SAFETY: enabling X2APIC mode allows accessing APIC's control
                // registers through MSR accesses, so enabling it doesn't break
                // memory safety itself.
                unsafe {
                    write_msr(MSR_APIC_BASE, apic_base_x2_enabled);
                }
            }
        }
        // Set SW-enable in SPIV to enable IRQ delivery
        self.sw_enable();
    }

    fn eoi(&self) {
        RawX2Apic::eoi();
    }

    fn icr_write(&self, icr: u64) {
        RawX2Apic::icr_write(icr);
    }

    fn check_isr(&self, vector: usize) -> bool {
        RawX2Apic::check_isr(vector)
    }

    fn spiv_write(&self, vector: u8, enable: bool) {
        RawX2Apic::spiv_write(vector, enable);
    }

    fn sw_enable(&self) {
        RawX2Apic::sw_enable();
    }
}
