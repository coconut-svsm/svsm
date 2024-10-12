// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::percpu::this_cpu;
use crate::cpu::{irqs_disable, irqs_enable};
use core::arch::asm;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

/// Interrupt flag in RFLAGS register
const EFLAGS_IF: u64 = 1 << 9;

/// Unconditionally disable IRQs
///
/// # Safety
///
/// Callers need to take care of re-enabling IRQs.
#[inline(always)]
pub unsafe fn raw_irqs_disable() {
    asm!("cli", options(att_syntax, preserves_flags, nomem));
}

/// Unconditionally enable IRQs
///
/// # Safety
///
/// Callers need to make sure it is safe to enable IRQs. e.g. that no data
/// structures or locks which are accessed in IRQ handlers are used after IRQs
/// have been enabled.
#[inline(always)]
pub unsafe fn raw_irqs_enable() {
    asm!("sti", options(att_syntax, preserves_flags, nomem));

    // Now that interrupts are enabled, process any #HV events that may be
    // pending.
    if let Some(doorbell) = this_cpu().hv_doorbell() {
        doorbell.process_if_required();
    }
}

/// Query IRQ state on current CPU
///
/// # Returns
///
/// `true` when IRQs are enabled, `false` otherwise
#[inline(always)]
#[must_use = "Unused irqs_enabled() result - meant to be irq_enable()?"]
pub fn irqs_enabled() -> bool {
    // SAFETY: The inline assembly just reads the processors RFLAGS register
    // and does not change any state.
    let state: u64;
    unsafe {
        asm!("pushfq",
             "popq {}",
             out(reg) state,
             options(att_syntax, preserves_flags));
    };

    (state & EFLAGS_IF) == EFLAGS_IF
}

/// Query IRQ state on current CPU
///
/// # Returns
///
/// `false` when IRQs are enabled, `true` otherwise
#[inline(always)]
#[must_use = "Unused irqs_disabled() result - meant to be irq_disable()?"]
pub fn irqs_disabled() -> bool {
    !irqs_enabled()
}

/// This structure keeps track of PerCpu IRQ states. It tracks the original IRQ
/// state and how deep IRQ-disable calls have been nested. The use of atomics
/// is necessary for interior mutability and to make state modifications safe
/// wrt. to IRQs.
///
/// The original state needs to be stored to not accidentially enable IRQs in
/// contexts which have IRQs disabled by other means, e.g. in an exception or
/// NMI/HV context.
#[derive(Debug, Default)]
pub struct IrqState {
    /// IRQ state when count was `0`
    state: AtomicBool,
    /// Depth of IRQ-disabled nesting
    count: AtomicIsize,
    /// Make the type !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl IrqState {
    /// Create a new instance of `IrqState`
    pub fn new() -> Self {
        Self {
            state: AtomicBool::new(false),
            count: AtomicIsize::new(0),
            phantom: PhantomData,
        }
    }

    /// Increase IRQ-disable nesting level by 1. The method will disable IRQs.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure to match the number of `disable` calls
    /// with the number of `enable` calls.
    #[inline(always)]
    pub unsafe fn disable(&self) {
        let state = irqs_enabled();

        raw_irqs_disable();
        let val = self.count.fetch_add(1, Ordering::Relaxed);

        assert!(val >= 0);

        if val == 0 {
            self.state.store(state, Ordering::Relaxed)
        }
    }

    /// Decrease IRQ-disable nesting level by 1. The method will restore the
    /// original IRQ state when the nesting level reaches 0.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure to match the number of `disable` calls
    /// with the number of `enable` calls.
    #[inline(always)]
    pub unsafe fn enable(&self) {
        debug_assert!(irqs_disabled());

        let val = self.count.fetch_sub(1, Ordering::Relaxed);

        assert!(val > 0);

        if val == 1 {
            let state = self.state.load(Ordering::Relaxed);
            if state {
                raw_irqs_enable();
            }
        }
    }

    /// Returns the current nesting count
    ///
    /// # Returns
    ///
    /// Levels of IRQ-disable nesting currently active
    pub fn count(&self) -> isize {
        self.count.load(Ordering::Relaxed)
    }

    /// Changes whether interrupts will be enabled when the nesting count
    /// drops to zero.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the current nesting count is non-zero,
    /// and must ensure that the specified value is appropriate for the
    /// current environment.
    pub unsafe fn set_restore_state(&self, enabled: bool) {
        assert!(self.count.load(Ordering::Relaxed) != 0);
        self.state.store(enabled, Ordering::Relaxed);
    }
}

impl Drop for IrqState {
    /// This struct should never be dropped. Add a debug check in case it is
    /// dropped anyway.
    fn drop(&mut self) {
        let count = self.count.load(Ordering::Relaxed);
        assert_eq!(count, 0);
    }
}

/// And IRQ guard which saves the current IRQ state and disabled interrupts
/// upon creation. When the guard goes out of scope the previous IRQ state is
/// restored.
///
/// The struct implements the `Default` and `Drop` traits for easy use.
#[derive(Debug)]
#[must_use = "if unused previous IRQ state will be immediatly restored"]
pub struct IrqGuard {
    /// Make the type !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl IrqGuard {
    pub fn new() -> Self {
        // SAFETY: Safe because the struct implements `Drop`, which
        // restores the IRQ state saved here.
        unsafe {
            irqs_disable();
        }

        Self {
            phantom: PhantomData,
        }
    }
}

impl Default for IrqGuard {
    fn default() -> Self {
        IrqGuard::new()
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        // SAFETY: Safe because the irqs_enabled() call matches the
        // irqs_disabled() call during struct creation.
        unsafe {
            irqs_enable();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn irq_enable_disable() {
        assert!(irqs_disabled());
        unsafe {
            raw_irqs_enable();
            assert!(irqs_enabled());
            raw_irqs_disable();
            assert!(irqs_disabled());
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn irq_state() {
        assert!(irqs_disabled());
        unsafe {
            let state = IrqState::new();
            raw_irqs_enable();
            state.disable();
            assert!(irqs_disabled());
            state.disable();
            state.enable();
            assert!(irqs_disabled());
            state.enable();
            assert!(irqs_enabled());
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn irq_guard_test() {
        assert!(irqs_disabled());
        unsafe {
            raw_irqs_enable();
            assert!(irqs_enabled());
            let g1 = IrqGuard::new();
            assert!(irqs_disabled());
            drop(g1);
            assert!(irqs_enabled());
            raw_irqs_disable();
        }
    }
}
