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
/// Callers need to take care of re-enabling IRQs.
#[inline(always)]
pub fn raw_irqs_disable() {
    // SAFETY: Inline assembly to disable IRQs, which does not change any state
    // related to memory safety.
    unsafe {
        asm!("cli", options(att_syntax, preserves_flags, nomem));
    }
}

/// Unconditionally enable IRQs
///
/// Callers need to make sure it is safe to enable IRQs. e.g. that no data
/// structures or locks which are accessed in IRQ handlers are used after IRQs
/// have been enabled.
#[inline(always)]
pub fn raw_irqs_enable() {
    // SAFETY: Inline assembly to enable IRQs, which does not change any state
    // related to memory safety.
    unsafe {
        asm!("sti", options(att_syntax, preserves_flags, nomem));
    }

    // Now that interrupts are enabled, process any #HV events that may be
    // pending.
    this_cpu().process_hv_events_if_required();
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

    /// Increase IRQ-disable nesting level by 1. The method will not disable
    /// interrupts because it is assumed to be called when interrupts are
    /// already disabled.
    ///
    /// The caller needs to make sure to match the number of `push_nesting`
    /// calls with the number of `pop_nesting` calls.
    ///
    /// * `was_enabled` - indicates whether interrupts were enabled at the
    ///   time of nesting.  This may not be the current state of interrupts
    ///   because interrupts may have been disabled for architectural reasons
    ///   prior to his function being called.
    ///
    /// # Returns
    ///
    /// The previous nesting level.
    pub fn push_nesting(&self, was_enabled: bool) {
        debug_assert!(irqs_disabled());
        let val = self.count.fetch_add(1, Ordering::Relaxed);

        assert!(val >= 0);

        if val == 0 {
            self.state.store(was_enabled, Ordering::Relaxed)
        }
    }

    /// Increase IRQ-disable nesting level by 1. The method will disable IRQs.
    ///
    /// The caller needs to make sure to match the number of `disable` calls
    /// with the number of `enable` calls.
    #[inline(always)]
    pub fn disable(&self) {
        let state = irqs_enabled();

        raw_irqs_disable();

        self.push_nesting(state);
    }

    /// Decrease IRQ-disable nesting level by 1. The method will not restore
    /// the original IRQ state when the nesting level reaches 0.
    ///
    /// The caller needs to make sure to match the number of `pop_nesting`
    /// calls with the number of `push_nesting` calls.
    ///
    /// # Returns
    ///
    /// The new IRQ nesting level.
    pub fn pop_nesting(&self) -> isize {
        debug_assert!(irqs_disabled());

        let val = self.count.fetch_sub(1, Ordering::Relaxed);

        assert!(val > 0);

        val - 1
    }

    /// Decrease IRQ-disable nesting level by 1. The method will restore the
    /// original IRQ state when the nesting level reaches 0.
    ///
    /// The caller needs to make sure to match the number of `disable` calls
    /// with the number of `enable` calls.
    #[inline(always)]
    pub fn enable(&self) {
        if self.pop_nesting() == 0 {
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
    /// The caller must ensure that the current nesting count is non-zero,
    /// and must ensure that the specified value is appropriate for the
    /// current environment.
    pub fn set_restore_state(&self, enabled: bool) {
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
        // This struct implements `Drop`, which will restore the IRQ state
        // saved here.
        irqs_disable();

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
        // The irqs_enabled() call matches the irqs_disabled() call during
        // struct creation.
        irqs_enable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn irq_enable_disable() {
        let was_enabled = irqs_enabled();
        raw_irqs_enable();
        assert!(irqs_enabled());
        raw_irqs_disable();
        assert!(irqs_disabled());
        if was_enabled {
            raw_irqs_enable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn irq_state() {
        let state = IrqState::new();
        let was_enabled = irqs_enabled();
        raw_irqs_enable();
        state.disable();
        assert!(irqs_disabled());
        state.disable();
        state.enable();
        assert!(irqs_disabled());
        state.enable();
        assert!(irqs_enabled());
        if !was_enabled {
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn irq_guard_test() {
        let was_enabled = irqs_enabled();
        raw_irqs_enable();
        assert!(irqs_enabled());
        let g1 = IrqGuard::new();
        assert!(irqs_disabled());
        drop(g1);
        assert!(irqs_enabled());
        if !was_enabled {
            raw_irqs_disable();
        }
    }
}
