// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
use crate::cpu::{IrqGuard, TprGuard};
use core::marker::PhantomData;

/// Abstracts TPR and interrupt state handling when taking and releasing
/// locks. There are three implemenations:
///
///   * [IrqUnsafeLocking] implements the methods as no-ops and does not change
///     any IRQ or TPR state.
///   * [IrqGuardLocking] actually disables and enables IRQs in the methods,
///     ensuring that no interrupt can be taken while the lock is held.
///   * [TprGuardLocking] raises and lowers TPR while the lock is held,
///     ensuring that no higher priority interrupt can be taken while the lock
///     is held.  This will panic when attempting to acquire a lower priority
///     lock from a higher priority interrupt context.
pub trait IrqLocking {
    /// Associated helper function to modify TPR/interrupt state when a lock
    /// is acquired.  This is used by lock implementations and will return an
    /// instance of the object.
    ///
    /// # Returns
    ///
    /// New instance of implementing struct.
    fn acquire_lock() -> Self;
}

/// Implements the IRQ state handling methods as no-ops. Locks defined with
/// this state handler are not safe with respect to reentrancy due to
/// interrupt delivery.
#[derive(Debug, Default)]
pub struct IrqUnsafeLocking;

impl IrqLocking for IrqUnsafeLocking {
    fn acquire_lock() -> Self {
        Self {}
    }
}

/// Implements the state handling methods for locks that disable interrupts.
#[derive(Debug, Default)]
pub struct IrqGuardLocking {
    /// IrqGuard to keep track of IRQ state. IrqGuard implements Drop, which
    /// will re-enable IRQs when the struct goes out of scope.
    _guard: IrqGuard,
    /// Make type explicitly !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl IrqLocking for IrqGuardLocking {
    fn acquire_lock() -> Self {
        Self {
            _guard: IrqGuard::new(),
            phantom: PhantomData,
        }
    }
}

/// Implements the state handling methods for locks that raise and lower TPR.
#[derive(Debug, Default)]
pub struct TprGuardLocking<const TPR: usize> {
    /// TprGuard to keep track of IRQ state. TprGuard implements Drop, which
    /// will lower TPR as required when the struct goes out of scope.
    _guard: TprGuard,
    /// Make type explicitly !Send + !Sync
    phantom: PhantomData<*const ()>,
}

impl<const TPR: usize> IrqLocking for TprGuardLocking<TPR> {
    fn acquire_lock() -> Self {
        Self {
            _guard: TprGuard::raise(TPR),
            phantom: PhantomData,
        }
    }
}
