// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

pub const APIC_MSR_EOI: u32 = 0x80B;
pub const APIC_MSR_ISR: u32 = 0x810;
pub const APIC_MSR_ICR: u32 = 0x830;

// Returns the MSR offset and bitmask to identify a specific vector in an
// APIC register (IRR, ISR, or TMR).
pub fn apic_register_bit(vector: usize) -> (u32, u32) {
    let index: u8 = vector as u8;
    ((index >> 5) as u32, 1 << (index & 0x1F))
}
