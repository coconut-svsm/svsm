// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::common::*;
use crate::types::TPR_LOCK;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

/// A lock guard obtained from a [`SpinLock`]. This lock guard
/// provides exclusive access to the data protected by a [`SpinLock`],
/// ensuring that the lock is released when it goes out of scope.
///
/// # Examples
///
/// ```
/// use svsm::locking::SpinLock;
///
/// let data = 42;
/// let spin_lock = SpinLock::new(data);
///
/// {
///     let mut guard = spin_lock.lock();
///     *guard += 1; // Modify the protected data.
/// }; // Lock is automatically released when `guard` goes out of scope.
/// ```
#[derive(Debug)]
#[must_use = "if unused the SpinLock will immediately unlock"]
pub struct RawLockGuard<'a, T, I> {
    holder: &'a AtomicU64,
    data: &'a mut T,
    #[expect(dead_code)]
    irq_state: I,
}

/// Implements the behavior of the [`LockGuard`] when it is dropped
impl<T, I> Drop for RawLockGuard<'_, T, I> {
    /// Automatically releases the lock when the guard is dropped
    fn drop(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`LockGuard`] to
/// access the protected data.
impl<T, I> Deref for RawLockGuard<'_, T, I> {
    type Target = T;
    /// Provides read-only access to the protected data
    fn deref(&self) -> &T {
        self.data
    }
}

/// Implements the behavior of dereferencing the [`LockGuard`] to
/// access the protected data in a mutable way.
impl<T, I> DerefMut for RawLockGuard<'_, T, I> {
    /// Provides mutable access to the protected data
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

pub type LockGuard<'a, T> = RawLockGuard<'a, T, IrqUnsafeLocking>;
pub type LockGuardIrqSafe<'a, T> = RawLockGuard<'a, T, IrqGuardLocking>;
pub type LockGuardAnyTpr<'a, T, const TPR: usize> = RawLockGuard<'a, T, TprGuardLocking<TPR>>;

/// A simple ticket-spinlock implementation for protecting concurrent data
/// access.
///
/// Two variants are derived from this implementation:
///
///  * [`SpinLock`] for general use. This implementation is not safe for use in
///    IRQ handlers.
///  * [`SpinLockIrqSafe`] for protecting data that is accessed in IRQ context.
///
/// # Examples
///
/// ```
/// use svsm::locking::SpinLock;
///
/// let data = 42;
/// let spin_lock = SpinLock::new(data);
///
/// // Acquire the lock and modify the protected data.
/// {
///     let mut guard = spin_lock.lock();
///     *guard += 1;
/// }; // Lock is automatically released when `guard` goes out of scope.
///
/// // Try to acquire the lock without blocking
/// if let Some(mut guard) = spin_lock.try_lock() {
///     *guard += 2;
/// };
/// ```
#[derive(Debug, Default)]
pub struct RawSpinLock<T, I> {
    /// This atomic counter is incremented each time a thread attempts to
    /// acquire the lock. It helps to determine the order in which threads
    /// acquire the lock.
    current: AtomicU64,
    /// This counter represents the thread that currently holds the lock
    /// and has access to the protected data.
    holder: AtomicU64,
    /// This `UnsafeCell` is used to provide interior mutability of the
    /// protected data. That is, it allows the data to be accessed/modified
    /// while enforcing the locking mechanism.
    data: UnsafeCell<T>,
    /// Use generic type I in the struct without consuming space.
    phantom: PhantomData<fn(I)>,
}

unsafe impl<T: Send, I> Send for RawSpinLock<T, I> {}
unsafe impl<T: Send, I> Sync for RawSpinLock<T, I> {}

impl<T, I: IrqLocking> RawSpinLock<T, I> {
    /// Creates a new SpinLock instance with the specified initial data.
    ///
    /// # Examples
    ///
    /// ```
    /// use svsm::locking::SpinLock;
    ///
    /// let data = 42;
    /// let spin_lock = SpinLock::new(data);
    /// ```
    pub const fn new(data: T) -> Self {
        Self {
            current: AtomicU64::new(0),
            holder: AtomicU64::new(0),
            data: UnsafeCell::new(data),
            phantom: PhantomData,
        }
    }

    /// Acquires the lock, providing access to the protected data.
    ///
    /// # Examples
    ///
    /// ```
    /// use svsm::locking::SpinLock;
    ///
    /// let spin_lock = SpinLock::new(42);
    ///
    /// // Acquire the lock and modify the protected data.
    /// {
    ///     let mut guard = spin_lock.lock();
    ///     *guard += 1;
    /// }; // Lock is automatically released when `guard` goes out of scope.
    /// ```
    pub fn lock(&self) -> RawLockGuard<'_, T, I> {
        let irq_state = I::acquire_lock();

        let ticket = self.current.fetch_add(1, Ordering::Relaxed);
        loop {
            let h = self.holder.load(Ordering::Acquire);
            if h == ticket {
                break;
            }
            core::hint::spin_loop();
        }
        RawLockGuard {
            holder: &self.holder,
            data: unsafe { &mut *self.data.get() },
            irq_state,
        }
    }

    /// Execute function F while holding the lock.
    ///
    /// # Examples
    ///
    /// ```
    /// use svsm::locking::SpinLock;
    ///
    /// let spin_lock = SpinLock::new(42);
    ///
    /// // Do some actions while holding the lock.
    /// // Lock is automatically taken and released.
    /// spin_lock.locked_do(|s| {
    ///     *s += 1;
    /// });
    /// ```
    pub fn locked_do<R, F: FnMut(&mut T) -> R>(&self, mut f: F) -> R {
        let mut l = self.lock();
        f(&mut (*l))
    }

    /// This method tries to acquire the lock without blocking. If the
    /// lock is not available, it returns `None`. If the lock is
    /// successfully acquired, it returns a [`LockGuard`] that automatically
    /// releases the lock when it goes out of scope.
    pub fn try_lock(&self) -> Option<RawLockGuard<'_, T, I>> {
        let irq_state = I::acquire_lock();

        let current = self.current.load(Ordering::Relaxed);
        let holder = self.holder.load(Ordering::Acquire);

        if current == holder {
            let result = self.current.compare_exchange(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            );
            if result.is_ok() {
                return Some(RawLockGuard {
                    holder: &self.holder,
                    data: unsafe { &mut *self.data.get() },
                    irq_state,
                });
            }
        }

        None
    }
}

pub type SpinLock<T> = RawSpinLock<T, IrqUnsafeLocking>;
pub type SpinLockIrqSafe<T> = RawSpinLock<T, IrqGuardLocking>;
pub type SpinLockAnyTpr<T, const TPR: usize> = RawSpinLock<T, TprGuardLocking<TPR>>;
pub type SpinLockTpr<T> = SpinLockAnyTpr<T, { TPR_LOCK }>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::irq_state::{raw_get_tpr, raw_irqs_disable, raw_irqs_enable};
    use crate::cpu::{irqs_disabled, irqs_enabled};
    use crate::types::TPR_LOCK;

    #[test]
    fn test_spin_lock() {
        let spin_lock = SpinLock::new(0);

        let mut guard = spin_lock.lock();
        *guard += 1;

        // Ensure the locked data is updated.
        assert_eq!(*guard, 1);

        // Try to lock again; it should fail and return None.
        let try_lock_result = spin_lock.try_lock();
        assert!(try_lock_result.is_none());
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn spin_lock_irq_unsafe() {
        let was_enabled = irqs_enabled();
        raw_irqs_enable();

        let spin_lock = SpinLock::new(0);
        let guard = spin_lock.lock();
        assert!(irqs_enabled());
        drop(guard);
        assert!(irqs_enabled());

        if !was_enabled {
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn spin_lock_irq_safe() {
        let was_enabled = irqs_enabled();
        raw_irqs_enable();

        let spin_lock = SpinLockIrqSafe::new(0);
        let guard = spin_lock.lock();
        assert!(irqs_disabled());
        drop(guard);
        assert!(irqs_enabled());

        if !was_enabled {
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn spin_trylock_irq_safe() {
        let was_enabled = irqs_enabled();
        raw_irqs_enable();

        let spin_lock = SpinLockIrqSafe::new(0);

        // IRQs are enabled - taking the lock must succeed and disable IRQs
        let g1 = spin_lock.try_lock();
        assert!(g1.is_some());
        assert!(irqs_disabled());

        // Release lock and check if that enables IRQs
        drop(g1);
        assert!(irqs_enabled());

        // Leave with IRQs configured as test was entered.
        if !was_enabled {
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn spin_trylock_tpr() {
        assert_eq!(raw_get_tpr(), 0);

        let spin_lock = SpinLockTpr::new(0);

        // TPR is zero - taking the lock must succeed and raise TPR.
        let g1 = spin_lock.try_lock();
        assert!(g1.is_some());
        assert_eq!(raw_get_tpr(), TPR_LOCK);

        // Release lock and check if that resets TPR.
        drop(g1);
        assert_eq!(raw_get_tpr(), 0);
    }
}
