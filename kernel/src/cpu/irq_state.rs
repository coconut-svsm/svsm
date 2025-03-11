// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::percpu::this_cpu;
use crate::cpu::{irqs_disable, irqs_enable, lower_tpr, raise_tpr};
use core::arch::asm;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Interrupt flag in RFLAGS register
pub const EFLAGS_IF: usize = 1 << 9;

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
    let state: usize;
    // SAFETY: The inline assembly just reads the processors RFLAGS register
    // and does not change any state.
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

/// Converts an interrupt vector to a TPR value.
#[inline(always)]
pub fn tpr_from_vector(vector: usize) -> usize {
    // TPR is the high four bits of the vector number.
    vector >> 4
}

/// Unconditionally set TPR.
///
/// Callers need to ensure that the selected TPR is appropriate for the
/// current context.
///
/// * `tpr_value` - the new TPR value.
#[inline(always)]
pub fn raw_set_tpr(tpr_value: usize) {
    // SAFETY: Inline assembly to change TPR, which does not change any state
    // related to memory safety.
    unsafe {
        asm!("mov {tpr}, %cr8",
             tpr = in(reg) tpr_value,
             options(att_syntax));
    }
}

/// Query IRQ state on current CPU
///
/// # Returns
///
/// The current TPR.
#[inline(always)]
pub fn raw_get_tpr() -> usize {
    // SAFETY: The inline assembly just reads the TPR register and does not
    // change any state.
    unsafe {
        let mut ret: usize;
        asm!("movq %cr8, {tpr}",
             tpr = out(reg) ret,
             options(att_syntax));
        ret
    }
}

const TPR_LIMIT: usize = 16;

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
    /// Depth of IRQ-disabled nesting.  Index 0 specifies the count of
    /// IRQ disables and the remaining indices specify the nesting count
    /// for eached raised TPR level.
    counts: [AtomicI32; TPR_LIMIT],
    /// Make the type !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl IrqState {
    /// Create a new instance of `IrqState`
    pub fn new() -> Self {
        Self {
            state: AtomicBool::new(false),
            counts: Default::default(),
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
        let val = self.counts[0].fetch_add(1, Ordering::Relaxed);

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
    pub fn pop_nesting(&self) -> i32 {
        debug_assert!(irqs_disabled());

        let val = self.counts[0].fetch_sub(1, Ordering::Relaxed);

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
    pub fn count(&self) -> i32 {
        self.counts[0].load(Ordering::Relaxed)
    }

    /// Changes whether interrupts will be enabled when the nesting count
    /// drops to zero.
    ///
    /// The caller must ensure that the current nesting count is non-zero,
    /// and must ensure that the specified value is appropriate for the
    /// current environment.
    pub fn set_restore_state(&self, enabled: bool) {
        assert!(self.counts[0].load(Ordering::Relaxed) != 0);
        self.state.store(enabled, Ordering::Relaxed);
    }

    /// Increments TPR.
    ///
    /// The caller must ensure that a `raise_tpr()` call is followed by a
    /// matching call to `lower_tpr()`.
    ///
    /// * `tpr_value` - The new TPR value.  Must be greater than or equal to
    ///   the current TPR value.
    #[inline(always)]
    pub fn raise_tpr(&self, tpr_value: usize) {
        assert!(tpr_value > 0 && tpr_value >= raw_get_tpr());
        raw_set_tpr(tpr_value);

        // Increment the count of requests to raise to this TPR to indicate
        // the number of execution contexts that require this TPR.
        self.counts[tpr_value].fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements TPR.
    ///
    /// The caller must ensure that a `lower` call balances a preceding
    /// `raise` call to the indicated level.
    ///
    /// * `tpr_value` - The TPR from which the caller would like to lower.
    ///   Must be less than or equal to the current TPR.
    #[inline(always)]
    pub fn lower_tpr(&self, tpr_value: usize) {
        let current_tpr = raw_get_tpr();
        debug_assert!(tpr_value <= current_tpr);

        // Decrement the count of execution contexts requiring this raised
        // TPR.
        let count = self.counts[tpr_value].fetch_sub(1, Ordering::Relaxed);
        debug_assert!(count > 0);

        if count == 1 && tpr_value >= current_tpr {
            // Find the highest TPR that is still required.
            for new_tpr in (0..tpr_value).rev() {
                if self.counts[new_tpr].load(Ordering::Relaxed) != 0 {
                    raw_set_tpr(new_tpr);
                    return;
                }
            }

            // No TPR is still in use, so lower to zero.
            raw_set_tpr(0);
        }
    }
}

impl Drop for IrqState {
    /// This struct should never be dropped. Add a debug check in case it is
    /// dropped anyway.
    fn drop(&mut self) {
        for count in &self.counts {
            assert_eq!(count.load(Ordering::Relaxed), 0);
        }
    }
}

/// And IRQ guard which saves the current IRQ state and disabled interrupts
/// upon creation. When the guard goes out of scope the previous IRQ state is
/// restored.
///
/// The struct implements the `Default` and `Drop` traits for easy use.
#[derive(Debug)]
#[must_use = "if unused previous IRQ state will be immediately restored"]
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

/// A TPR guard which raises TPR upon creation.  When the guard goes out of
/// scope, TPR is lowered to the highest active TPR.
///
/// The struct implements the `Drop` trait for easy use.
#[derive(Debug, Default)]
#[must_use = "if unused previous TPR will be immediately restored"]
pub struct TprGuard {
    tpr_value: usize,

    /// Make the type !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl TprGuard {
    pub fn raise(tpr_value: usize) -> Self {
        // SAFETY: Safe because the struct implements `Drop, which restores
        // TPR state.
        raise_tpr(tpr_value);

        Self {
            tpr_value,
            phantom: PhantomData,
        }
    }
}

impl Drop for TprGuard {
    fn drop(&mut self) {
        // Lower TPR from the value to which it was raised.
        lower_tpr(self.tpr_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::ipi::ipi_available;
    use crate::platform::SVSM_PLATFORM;

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

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn tpr_test() {
        if SVSM_PLATFORM.use_interrupts() || ipi_available() {
            assert_eq!(raw_get_tpr(), 0);
            raise_tpr(7);
            assert_eq!(raw_get_tpr(), 7);
            raise_tpr(8);
            assert_eq!(raw_get_tpr(), 8);
            lower_tpr(8);
            assert_eq!(raw_get_tpr(), 7);
            lower_tpr(7);
            assert_eq!(raw_get_tpr(), 0);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn tpr_guard_test() {
        if SVSM_PLATFORM.use_interrupts() || ipi_available() {
            assert_eq!(raw_get_tpr(), 0);
            // Test in-order raise/lower.
            let g1 = TprGuard::raise(8);
            assert_eq!(raw_get_tpr(), 8);
            let g2 = TprGuard::raise(9);
            assert_eq!(raw_get_tpr(), 9);
            drop(g2);
            assert_eq!(raw_get_tpr(), 8);
            drop(g1);
            assert_eq!(raw_get_tpr(), 0);
            // Test out-of-order raise/lower.
            let g1 = TprGuard::raise(8);
            assert_eq!(raw_get_tpr(), 8);
            let g2 = TprGuard::raise(9);
            assert_eq!(raw_get_tpr(), 9);
            drop(g1);
            assert_eq!(raw_get_tpr(), 9);
            drop(g2);
            assert_eq!(raw_get_tpr(), 0);
        }
    }
}
