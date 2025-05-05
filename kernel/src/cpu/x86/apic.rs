// SPDX-License-Identifier: MIT
//
// Copyright (c) SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use core::cell::OnceCell;

pub trait ApicAccess: core::fmt::Debug {
    /// Updates the APIC_BASE MSR by reading the current value, applying the
    /// `and_mask`, then the `or_mask`, and writing back the new value.
    ///
    /// # Arguments
    ///
    /// `and_mask` - Value to bitwise AND with the current value.
    /// `or_mask` - Value to bitwise OR with the current value, after
    ///             `and_mask` has been applied.
    fn update_apic_base(&self, and_mask: u64, or_mask: u64);

    /// Write a value to an APIC offset
    ///
    /// # Arguments
    ///
    /// - `offset` - Offset into the APIC
    /// - `value` - Value to write at `offset`
    fn apic_write(&self, offset: usize, value: u64);

    /// Read value from APIC offset
    ///
    /// # Arguments
    ///
    /// - `offset` - Offset into the APIC
    ///
    /// # Returns
    ///
    /// The value read from APIC `offset`.
    fn apic_read(&self, offset: usize) -> u64;

    /// ICR access method - defaults to writing to the APIC.ICR register.
    ///
    /// # Arguments
    ///
    /// `icr` - ICR value to write
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, [`SvsmError`] on failure.
    fn icr_write(&self, icr: u64) -> Result<(), SvsmError> {
        self.apic_write(APIC_OFFSET_ICR, icr);
        Ok(())
    }

    /// EOI Method - defaults to writing to APIC.EOI register
    fn eoi(&self) {
        self.apic_write(APIC_OFFSET_EOI, 0);
    }
}

/// APIC Base MSR
pub const MSR_APIC_BASE: u32 = 0x1B;

/// Local APIC ID register MSR offset
pub const APIC_OFFSET_ID: usize = 0x2;
/// End-of-Interrupt register MSR offset
pub const APIC_OFFSET_EOI: usize = 0xB;
/// Spurious-Interrupt-Register MSR offset
pub const APIC_OFFSET_SPIV: usize = 0xF;
/// Interrupt-Service-Register base MSR offset
pub const APIC_OFFSET_ISR: usize = 0x10;
/// Interrupt-Control-Register register MSR offset
pub const APIC_OFFSET_ICR: usize = 0x30;
/// SELF-IPI register MSR offset (x2APIC only)
pub const APIC_OFFSET_SELF_IPI: usize = 0x3F;

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
pub struct X86Apic {
    access: OnceCell<&'static dyn ApicAccess>,
}

// APIC enable masks
const APIC_ENABLE_MASK: u64 = 0x800;
const APIC_X2_ENABLE_MASK: u64 = 0x400;

impl X86Apic {
    /// Returns the ApicAccess object.
    fn regs(&self) -> &'static dyn ApicAccess {
        *self.access.get().expect("ApicAccessor not set!")
    }

    /// Initialize the ApicAccessor - Must be called before X86APIC can be used.
    ///
    /// # Arguments
    ///
    /// - `accessor` - Static object implementing [`ApicAccess`] trait.
    ///
    /// # Panics
    ///
    /// This function panics when the `ApicAccessor` has already been set.
    pub fn set_accessor(&self, accessor: &'static dyn ApicAccess) {
        self.access
            .set(accessor)
            .expect("ApicAccessor already set!");
    }

    /// Creates a new instance of [`X86Apic`]
    pub fn new() -> Self {
        Self {
            access: OnceCell::new(),
        }
    }

    /// Enables to APIC in X2APIC mode.
    pub fn enable(&self) {
        let enable_mask: u64 = APIC_ENABLE_MASK | APIC_X2_ENABLE_MASK;
        self.regs().update_apic_base(!enable_mask, enable_mask);
    }

    /// Enable the APIC-Software-Enable bit.
    pub fn sw_enable(&self) {
        self.spiv_write(0xff, true);
    }

    /// Get APIC ID
    #[inline(always)]
    pub fn id(&self) -> u32 {
        self.regs().apic_read(APIC_OFFSET_ID) as u32
    }

    /// Sends an EOI message
    #[inline(always)]
    pub fn eoi(&self) {
        self.regs().eoi();
    }

    /// Writes the APIC ICR register
    ///
    /// # Arguments
    ///
    /// - `icr` - Value to write to the ICR register
    #[inline(always)]
    pub fn icr_write(&self, icr: u64) {
        self.regs()
            .icr_write(icr)
            .expect("Failed to write APIC.ICR");
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
    pub fn check_isr(&self, vector: usize) -> bool {
        // Examine the APIC ISR to determine whether this interrupt vector is
        // active.  If so, it is assumed to be an external interrupt.
        let (offset, mask) = apic_register_bit(vector);
        (self.regs().apic_read(APIC_OFFSET_ISR + offset) & mask as u64) != 0
    }

    /// Set Spurious-Interrupt-Vector Register
    ///
    /// # Arguments
    ///
    /// - `vector` - The IRQ vector to deliver spurious interrupts to.
    /// - `enable` - Value of the APIC-Software-Enable bit.
    #[inline(always)]
    pub fn spiv_write(&self, vector: u8, enable: bool) {
        let apic_spiv: u64 = if enable { APIC_SPIV_SW_ENABLE_MASK } else { 0 }
            | ((vector as u64) & APIC_SPIV_VECTOR_MASK);
        self.regs().apic_write(APIC_OFFSET_SPIV, apic_spiv);
    }
}

/// Initialize the APIC  by setting an accessor object. This function
/// does not enable the APIC.
///
/// # Arguments
///
/// `accessor` - Object implenting [`ApicAccess`] trait which provides the
///              low-level access methods to access the APIC registers.
///
/// # Panics
///
/// This method can only be called once per `PerCpu` object, panics on the
/// second call.
pub fn apic_initialize(accessor: &'static dyn ApicAccess) {
    this_cpu().initialize_apic(accessor);
}

/// Enables the X86 local APIC in X2APIC mode by writing to MSR_APIC_BASE.
pub fn apic_enable() {
    this_cpu().get_apic().enable();
}

/// Enables software IRQs in the X86 local APIC by setting the SPIC.SW_ENABLE
/// bit.
pub fn apic_sw_enable() {
    this_cpu().get_apic().sw_enable();
}

/// Sends an IPI specified by the X86 ICR value.
pub fn apic_post_irq(icr: u64) {
    this_cpu().get_apic().icr_write(icr);
}

/// Send an EOI message
pub fn apic_eoi() {
    this_cpu().get_apic().eoi();
}

/// Check whether a given IRQ vector is currently being serviced by returning
/// the value of its ISR bit from X2APIC.
///
/// # Arguments
///
/// - `vector` - The IRQ vector for which to check the ISR bit.
///
/// # Returns
///
/// Returns `True` when the ISR bit for the vector is 1, `False` otherwise.
pub fn apic_in_service(vector: usize) -> bool {
    this_cpu().get_apic().check_isr(vector)
}
