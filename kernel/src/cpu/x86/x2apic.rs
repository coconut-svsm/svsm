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
/// Spurious-Interrupt-Register MSR offset
pub const MSR_X2APIC_SPIV: u32 = 0x80F;
/// Interrupt-Service-Register base MSR offset
pub const MSR_X2APIC_ISR: u32 = 0x810;
/// Interrupt-Control-Register register MSR offset
pub const MSR_X2APIC_ICR: u32 = 0x830;

const MSR_APIC_BASE: u32 = 0x1B;
const APIC_ENABLE_MASK: u64 = 0x800;
const APIC_X2_ENABLE_MASK: u64 = 0x400;

// SPIV bits
const APIC_SPIV_VECTOR_MASK: u64 = (1u64 << 8) - 1;
const APIC_SPIV_SW_ENABLE_MASK: u64 = 1 << 8;

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
    // Set SW-enable in SPIV to enable IRQ delivery
    x2apic_sw_enable();
}

/// Send an End-of-Interrupt notification to the X2APIC.
pub fn x2apic_eoi() {
    // SAFETY: writing to EOI MSR doesn't break memory safety.
    unsafe { write_msr(MSR_X2APIC_EOI, 0) };
}

/// Check whether a give IRQ vector is currently being serviced by returning
/// the value of its ISR bit from X2APIC.
///
/// # Arguments
///
/// - `vector` - The IRQ vector for which to check the ISR bit.
///
/// # Returns
///
/// Returns `True` when the ISR bit for the vector is 1, `False` otherwise.
pub fn x2apic_in_service(vector: usize) -> bool {
    // Examine the APIC ISR to determine whether this interrupt vector is
    // active.  If so, it is assumed to be an external interrupt.
    let (msr, mask) = apic_register_bit(vector);
    (read_msr(MSR_X2APIC_ISR + msr) & mask as u64) != 0
}

/// Write a command to the Interrupt Command Register.
///
/// # Arguments
///
/// - `icr` - The 64-bit value describing the interrupt command.
pub fn x2apic_icr_write(icr: u64) {
    // SAFETY: writing to ICR MSR doesn't break memory safety.
    unsafe { write_msr(MSR_X2APIC_ICR, icr) };
}

/// Set Spurious-Interrupt-Vector Register
///
/// # Arguments
///
/// - `vector` - The IRQ vector to deliver spurious interrupts to.
/// - `enable` - Value of the APIC-Software-Enable bit.
pub fn x2apic_spiv_write(vector: u8, enable: bool) {
    let apic_spiv: u64 = if enable { APIC_SPIV_SW_ENABLE_MASK } else { 0 }
        | ((vector as u64) & APIC_SPIV_VECTOR_MASK);
    // SAFETY: Setting bits in SIPV does not break memory safety.
    unsafe { write_msr(MSR_X2APIC_SPIV, apic_spiv) };
}

/// Enable the APIC-Software-Enable bit.
pub fn x2apic_sw_enable() {
    x2apic_spiv_write(0xff, true);
}
