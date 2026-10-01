// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::common::*;
use crate::types::TPR_LOCK;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const NO_CPU: u32 = u32::MAX;

/// Returns the index of the current running CPU. Used to keep track
/// of the holder of a lock.
#[inline]
fn current_cpu_id() -> u32 {
    #[cfg(target_os = "none")]
    {
        crate::cpu::percpu::try_this_cpu()
            .map(|cpu| cpu.get_cpu_index() as u32)
            .unwrap_or(NO_CPU)
    }
    #[cfg(not(target_os = "none"))]
    {
        NO_CPU
    }
}

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
    cpu: &'a AtomicU32,
    /// Pointer to the protected data. This relaxes the borrow checker
    /// when implementing `map()` and related methods, and prevents
    /// introducing LLVM `noalias` violations, according to a comment
    /// in the equivalent guard structure for RwLock in the standard
    /// library.
    data: NonNull<T>,
    _variance: PhantomData<&'a mut T>,
    irq_state: I,
}

impl<'a, T, I: IrqLocking> RawLockGuard<'a, T, I> {
    pub fn map<U, F>(orig: Self, f: F) -> RawLockGuard<'a, U, I>
    where
        F: FnOnce(&mut T) -> &mut U,
    {
        let mut orig = ManuallyDrop::new(orig);
        let holder = orig.holder;
        let cpu = orig.cpu;
        // Move the original IRQ state out of drop.
        // SAFETY: we are really reading from a reference, so the source
        // pointer is safe. The original guard is behind `ManuallyDrop`,
        // so only the copy we just make will invoke drop.
        let irq_state = unsafe { core::ptr::read(&raw const orig.irq_state) };
        let value = f(&mut *orig);
        RawLockGuard {
            holder,
            cpu,
            data: NonNull::from(value),
            _variance: PhantomData,
            irq_state,
        }
    }
}

// SAFETY: RawLockGuard does not automatically implement Sync because it
// contains a `NonNull`, which is guarded by the lock's behavior.
unsafe impl<T: Sync, I: Sync> Sync for RawLockGuard<'_, T, I> {}

// SAFETY: RawLockGuard does not automatically implement Send because it
// contains a `NonNull`, which is guarded by the lock's behavior.
unsafe impl<T: Send, I: Send> Send for RawLockGuard<'_, T, I> {}

/// Implements the behavior of the [`LockGuard`] when it is dropped
impl<T, I> Drop for RawLockGuard<'_, T, I> {
    /// Automatically releases the lock when the guard is dropped
    fn drop(&mut self) {
        self.cpu.store(NO_CPU, Ordering::Relaxed);
        self.holder.fetch_add(1, Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`LockGuard`] to
/// access the protected data.
impl<T, I> Deref for RawLockGuard<'_, T, I> {
    type Target = T;
    /// Provides read-only access to the protected data
    fn deref(&self) -> &T {
        // SAFETY: a spinlock guard guarantees exclusive access
        unsafe { self.data.as_ref() }
    }
}

/// Implements the behavior of dereferencing the [`LockGuard`] to
/// access the protected data in a mutable way.
impl<T, I> DerefMut for RawLockGuard<'_, T, I> {
    /// Provides mutable access to the protected data
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: a spinlock guard guarantees exclusive access
        unsafe { self.data.as_mut() }
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
#[derive(Debug)]
pub struct RawSpinLock<T, I> {
    /// This atomic counter is incremented each time a thread attempts to
    /// acquire the lock. It helps to determine the order in which threads
    /// acquire the lock.
    current: AtomicU64,
    /// This counter represents the thread that currently holds the lock
    /// and has access to the protected data.
    holder: AtomicU64,
    /// Index of the CPU currently holding the lock, or [`NO_CPU`] when the
    /// lock is free, or when CPU index cannot be determined.
    cpu: AtomicU32,
    /// This `UnsafeCell` is used to provide interior mutability of the
    /// protected data. That is, it allows the data to be accessed/modified
    /// while enforcing the locking mechanism.
    data: UnsafeCell<T>,
    /// Use generic type I in the struct without consuming space.
    phantom: PhantomData<fn(I)>,
}

// SAFETY: A well-formed lock is always `Send`.
unsafe impl<T, I> Send for RawSpinLock<T, I> {}
// SAFETY: A well-formed lock is always `Sync`.
unsafe impl<T, I> Sync for RawSpinLock<T, I> {}

impl<T: Default + Send, I: IrqLocking> Default for RawSpinLock<T, I> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// A lock can only be formed if the type it protects is `Send`, since the
/// contents of the lock will be sent to different threads.
impl<T: Send, I: IrqLocking> RawSpinLock<T, I> {
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
            cpu: AtomicU32::new(NO_CPU),
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

        let cpu = current_cpu_id();
        let ticket = self.current.fetch_add(1, Ordering::Relaxed);
        loop {
            let h = self.holder.load(Ordering::Acquire);
            if h == ticket {
                break;
            }
            if cpu != NO_CPU && self.cpu.load(Ordering::Relaxed) == cpu {
                panic!("Detected reentrant spinlock deadlock on CPU {cpu}");
            }
            core::hint::spin_loop();
        }
        self.cpu.store(cpu, Ordering::Relaxed);
        RawLockGuard {
            holder: &self.holder,
            cpu: &self.cpu,
            // SAFETY: the UnsafeCell is initialized on construction, so the
            // pointer can never be NULL
            data: unsafe { NonNull::new_unchecked(self.data.get()) },
            _variance: PhantomData,
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
                self.cpu.store(current_cpu_id(), Ordering::Relaxed);
                return Some(RawLockGuard {
                    holder: &self.holder,
                    cpu: &self.cpu,
                    // SAFETY: the UnsafeCell is initialized on construction, so the
                    // pointer can never be NULL
                    data: unsafe { NonNull::new_unchecked(self.data.get()) },
                    _variance: PhantomData,
                    irq_state,
                });
            }
        }

        None
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows the `RawSpinLock` mutably, no actual locking needs to take place --
    /// the mutable borrow statically guarantees no new locks can be acquired while this reference
    /// exists.
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: the returned reference carries an exclusive borrow on self,
        // thereby establishing exclusive access.
        unsafe { &mut *self.data.get() }
    }
}

impl<T: Send, I: IrqLocking> From<T> for RawSpinLock<T, I> {
    fn from(value: T) -> Self {
        Self::new(value)
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
