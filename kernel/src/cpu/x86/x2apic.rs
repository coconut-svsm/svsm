// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation
// Copyright (c) SUSE LLC
//
// Author: Jon Lange <jlange@microsoft.com>
// Author: Joerg Roedel <jroedel@suse.de>

use super::{ApicAccess, MSR_APIC_BASE};
use crate::cpu::msr::{read_msr, write_msr};

/// X2APIC Base MSR
pub const MSR_X2APIC_BASE: u32 = 0x800;
/// End-of-Interrupt register MSR offset
pub const MSR_X2APIC_EOI: u32 = 0x80B;
/// Spurious-Interrupt-Register MSR offset
pub const MSR_X2APIC_SPIV: u32 = 0x80F;
/// Interrupt-Service-Register base MSR offset
pub const MSR_X2APIC_ISR: u32 = 0x810;
/// Interrupt-Control-Register register MSR offset
pub const MSR_X2APIC_ICR: u32 = 0x830;
/// SELF-IPI register MSR offset
pub const MSR_X2APIC_SELF_IPI: u32 = 0x83F;

#[derive(Debug)]
pub struct X2ApicAccessor {}

impl ApicAccess for X2ApicAccessor {
    fn update_apic_base(&self, and_mask: u64, or_mask: u64) {
        let current_value = read_msr(MSR_APIC_BASE);
        let new_value = (current_value & and_mask) | or_mask;

        if current_value != new_value {
            // SAFETY: Writes to MSR_APIC_BASE to not impact memory safety.
            unsafe {
                write_msr(MSR_APIC_BASE, new_value);
            }
        }
    }

    fn apic_write(&self, offset: usize, value: u64) {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        // SAFETY: Writes to X2APIC MSRs never harms memory safety.
        unsafe { write_msr(msr, value) };
    }

    fn apic_read(&self, offset: usize) -> u64 {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();
        read_msr(msr)
    }
}

pub static X2APIC_ACCESSOR: X2ApicAccessor = X2ApicAccessor {};
