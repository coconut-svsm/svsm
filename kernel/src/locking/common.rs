// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
use crate::cpu::IrqGuard;
use core::marker::PhantomData;

/// Abstracts IRQ state handling when taking and releasing locks. There are two
/// implemenations:
///
///   * [IrqUnsafeLocking] implements the methods as no-ops and does not change
///     any IRQ state.
///   * [IrqSafeLocking] actually disables and enables IRQs in the methods,
///     making a lock IRQ-safe by using this structure.
pub trait IrqLocking {
    /// Associated helper function to disable IRQs and create an instance of
    /// the implementing struct. This is used by lock implementations.
    ///
    /// # Returns
    ///
    /// New instance of implementing struct.
    fn irqs_disable() -> Self;
}

/// Implements the IRQ state handling methods as no-ops. For use it IRQ-unsafe
/// locks.
#[derive(Debug, Default)]
pub struct IrqUnsafeLocking;

impl IrqLocking for IrqUnsafeLocking {
    fn irqs_disable() -> Self {
        Self {}
    }
}

/// Properly implements the IRQ state handling methods. For use it IRQ-safe
/// locks.
#[derive(Debug, Default)]
pub struct IrqSafeLocking {
    /// IrqGuard to keep track of IRQ state. IrqGuard implements Drop, which
    /// will re-enable IRQs when the struct goes out of scope.
    _guard: IrqGuard,
    /// Make type explicitly !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl IrqLocking for IrqSafeLocking {
    fn irqs_disable() -> Self {
        Self {
            _guard: IrqGuard::new(),
            phantom: PhantomData,
        }
    }
}
