// SPDX-License-Identifier: MIT
//
// Copyright (c) SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::marker::PhantomData;

pub trait ApicAccess {
    /// Write a value to an APIC offset
    ///
    /// # Arguments
    ///
    /// - `offset` - Offset into the APIC
    /// - `value` - Value to write at `offset`
    fn apic_write(offset: usize, value: u64);

    /// Read value from APIC offset
    ///
    /// # Arguments
    ///
    /// - `offset` - Offset into the APIC
    ///
    /// # Returns
    ///
    /// The value read from APIC `offset`.
    fn apic_read(offset: usize) -> u64;
}

/// End-of-Interrupt register MSR offset
pub const APIC_OFFSET_EOI: usize = 0xB;
/// Spurious-Interrupt-Register MSR offset
pub const APIC_OFFSET_SPIV: usize = 0xF;
/// Interrupt-Service-Register base MSR offset
pub const APIC_OFFSET_ISR: usize = 0x10;
/// Interrupt-Control-Register register MSR offset
pub const APIC_OFFSET_ICR: usize = 0x30;

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
fn apic_register_bit(vector: usize) -> (usize, u32) {
    let index: u8 = vector as u8;
    ((index >> 5) as usize, 1 << (index & 0x1F))
}

#[derive(Debug, Default)]
pub struct RawX86Apic<A> {
    phantom: PhantomData<A>,
}

impl<A: ApicAccess> RawX86Apic<A> {
    /// Creates a new instance of [`RawX86Apic`]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    /// Sends an EOI message
    #[inline(always)]
    pub fn eoi() {
        A::apic_write(APIC_OFFSET_EOI, 0);
    }

    /// Writes the APIC ICR register
    ///
    /// # Arguments
    ///
    /// - `icr` - Value to write to the ICR register
    #[inline(always)]
    pub fn icr_write(icr: u64) {
        A::apic_write(APIC_OFFSET_ICR, icr);
    }

    /// Checks whether an IRQ vector is currently in service
    ///
    /// # Arguments
    ///
    /// - `vector` - Vector to check for
    ///
    /// # Returns
    ///
    /// Returns `True` when the vector is in service, `False` otherwise.
    #[inline(always)]
    pub fn check_isr(vector: usize) -> bool {
        // Examine the APIC ISR to determine whether this interrupt vector is
        // active.  If so, it is assumed to be an external interrupt.
        let (offset, mask) = apic_register_bit(vector);
        (A::apic_read(APIC_OFFSET_ISR + offset) & mask as u64) != 0
    }

    /// Set Spurious-Interrupt-Vector Register
    ///
    /// # Arguments
    ///
    /// - `vector` - The IRQ vector to deliver spurious interrupts to.
    /// - `enable` - Value of the APIC-Software-Enable bit.
    #[inline(always)]
    pub fn spiv_write(vector: u8, enable: bool) {
        let apic_spiv: u64 = if enable { APIC_SPIV_SW_ENABLE_MASK } else { 0 }
            | ((vector as u64) & APIC_SPIV_VECTOR_MASK);
        A::apic_write(APIC_OFFSET_SPIV, apic_spiv);
    }

    /// Enable the APIC-Software-Enable bit.
    pub fn sw_enable() {
        Self::spiv_write(0xff, true);
    }
}

pub trait X86Apic {
    /// Enables the APIC
    fn enable(&self);

    /// Sends an EOI message
    fn eoi(&self);

    /// Writes the APIC ICR register
    ///
    /// # Arguments
    ///
    /// - `icr` - Value to write to the ICR register
    fn icr_write(&self, icr: u64);

    /// Checks whether an IRQ vector is currently in service
    ///
    /// # Arguments
    ///
    /// - `vector` - Vector to check for
    ///
    /// # Returns
    ///
    /// Returns `True` when the vector is in service, `False` otherwise.
    fn check_isr(&self, vector: usize) -> bool;

    /// Set Spurious-Interrupt-Vector Register
    ///
    /// # Arguments
    ///
    /// - `vector` - The IRQ vector to deliver spurious interrupts to.
    /// - `enable` - Value of the APIC-Software-Enable bit.
    fn spiv_write(&self, vector: u8, enable: bool);

    /// Enable the APIC-Software-Enable bit.
    fn sw_enable(&self);
}
