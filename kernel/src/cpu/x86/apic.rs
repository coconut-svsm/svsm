// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation
// Copyright (c) SUSE LLC
//
// Author: Jon Lange <jlange@microsoft.com>
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::msr::{read_msr, write_msr};

/// End-of-Interrupt register MSR offset
pub const MSR_X2APIC_EOI: u32 = 0x80B;
/// Interrupt-Service-Register base MSR offset
pub const MSR_X2APIC_ISR: u32 = 0x810;
/// Interrupt-Control-Register register MSR offset
pub const MSR_X2APIC_ICR: u32 = 0x830;

const MSR_APIC_BASE: u32 = 0x1B;
const APIC_ENABLE_MASK: u64 = 0x800;
const APIC_X2_ENABLE_MASK: u64 = 0x400;

/// Get the MSR offset relative to a bitmap base MSR and the mask for the MSR
/// value to check for a specific vector bit being set in IRR, ISR, or TMR.
///
/// # Returns
///
/// A `(u32, u32)` tuple with the MSR offset as the first and the vector
/// bitmask as the second value.
pub fn apic_register_bit(vector: usize) -> (u32, u32) {
    let index: u8 = vector as u8;
    ((index >> 5) as u32, 1 << (index & 0x1F))
}

/// Enables the X2APIC by setting the AE and EXTD bits in the APIC base address
/// register.
pub fn x2apic_enable() {
    // Enable X2APIC mode.
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
