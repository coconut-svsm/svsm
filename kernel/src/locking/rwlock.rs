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
use core::sync::atomic::{AtomicU64, Ordering};

/// A guard that provides read access to the data protected by [`RWLock`]
#[derive(Debug)]
#[must_use = "if unused the RWLock will immediately unlock"]
pub struct RawReadLockGuard<'a, T, I> {
    /// Reference to the associated `AtomicU64` in the [`RWLock`]
    rwlock: &'a AtomicU64,
    /// Pointer to the protected data. This relaxes the borrow checker
    /// when implementing `map()` and related methods, and prevents
    /// introducing LLVM `noalias` violations, according to a comment
    /// in the equivalent guard structure in the standard library.
    data: NonNull<T>,
    /// IRQ state before and after critical section
    _irq_state: I,
}

impl<'a, T, I: IrqLocking> RawReadLockGuard<'a, T, I> {
    /// Creates a new `RawReadLockGuard` for a component of the backing data.
    pub fn map<U, F>(orig: Self, f: F) -> RawReadLockGuard<'a, U, I>
    where
        F: FnOnce(&T) -> &U,
    {
        // Ensure the original guard is never dropped
        let orig = ManuallyDrop::new(orig);
        let rwlock = orig.rwlock;
        // Move the original IRQ state out of drop.
        // SAFETY: we are really reading from a reference, so the source
        // pointer is safe. The original guard is behind `ManuallyDrop`,
        // so only the copy we just make will invoke drop.
        let _irq_state = unsafe { core::ptr::read(&orig._irq_state) };
        let value = f(&*orig);
        RawReadLockGuard {
            rwlock,
            data: NonNull::from(value),
            _irq_state,
        }
    }

    /// Splits a `RawReadLockGuard` for different components of the backing data.
    pub fn map_split<U, V, F>(
        orig: Self,
        f: F,
    ) -> (RawReadLockGuard<'a, U, I>, RawReadLockGuard<'a, V, I>)
    where
        F: FnOnce(&T) -> (&U, &V),
    {
        // Ensure the original guard is never dropped
        let orig = ManuallyDrop::new(orig);

        // Move the original IRQ state out of drop.
        // SAFETY: we are really reading from a reference, so the source
        // pointer is safe. The original guard is behind `ManuallyDrop`,
        // so only the copy we just make will invoke drop.
        let _irq_state = unsafe { core::ptr::read(&orig._irq_state) };

        // Increase the reader count by 1.
        let rwlock = orig.rwlock;
        rwlock.fetch_add(compose_val(1, 0), Ordering::Release);

        let (a, b) = f(&*orig);
        (
            RawReadLockGuard {
                rwlock,
                data: NonNull::from(a),
                _irq_state,
            },
            RawReadLockGuard {
                rwlock,
                data: NonNull::from(b),
                // Acquire a second IRQ guard
                _irq_state: I::acquire_lock(),
            },
        )
    }
}

/// Implements the behavior of the [`ReadLockGuard`] when it is dropped
impl<T, I> Drop for RawReadLockGuard<'_, T, I> {
    /// Release the read lock
    fn drop(&mut self) {
        self.rwlock.fetch_sub(compose_val(1, 0), Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`ReadLockGuard`] to
/// access the protected data.
impl<T, I> Deref for RawReadLockGuard<'_, T, I> {
    type Target = T;
    /// Allow reading the protected data through deref
    fn deref(&self) -> &T {
        // SAFETY: the pointer is valid by construction and never changed.
        // The guard guarantees no external mutable access.
        unsafe { self.data.as_ref() }
    }
}

pub type ReadLockGuard<'a, T> = RawReadLockGuard<'a, T, IrqUnsafeLocking>;
pub type ReadLockGuardIrqSafe<'a, T> = RawReadLockGuard<'a, T, IrqGuardLocking>;
pub type ReadLockGuardAnyTpr<'a, T, const TPR: usize> =
    RawReadLockGuard<'a, T, TprGuardLocking<TPR>>;

/// A guard that provides exclusive write access to the data protected by [`RWLock`]
#[derive(Debug)]
#[must_use = "if unused the RWLock will immediately unlock"]
pub struct RawWriteLockGuard<'a, T, I> {
    /// Reference to the associated `AtomicU64` in the [`RWLock`]
    rwlock: &'a AtomicU64,
    /// Pointer to the protected data. This relaxes the borrow checker
    /// when implementing `map()` and related methods, and prevents
    /// introducing LLVM `noalias` violations, according to a comment
    /// in the equivalent guard structure in the standard library.
    data: NonNull<T>,
    /// `NonNull` is covariant over `T`, so add a `PhantomData` field to enforce
    /// the correct invariance over `T`.
    _variance: PhantomData<&'a mut T>,
    /// IRQ state before and after critical section
    _irq_state: I,
}

impl<'a, T, I: IrqLocking> RawWriteLockGuard<'a, T, I> {
    /// Creates a new `RawWriteLockGuard` for a component of the backing data.
    pub fn map<U, F>(orig: Self, f: F) -> RawWriteLockGuard<'a, U, I>
    where
        F: FnOnce(&mut T) -> &mut U,
    {
        // Ensure the original guard is never dropped
        let mut orig = ManuallyDrop::new(orig);
        let rwlock = orig.rwlock;
        // Move the original IRQ state out of drop.
        // SAFETY: we are really reading from a reference, so the source
        // pointer is safe. The original guard is behind `ManuallyDrop`,
        // so only the copy we just make will invoke drop.
        let _irq_state = unsafe { core::ptr::read(&orig._irq_state) };

        let value = f(&mut *orig);
        RawWriteLockGuard {
            rwlock,
            data: NonNull::from(value),
            _variance: PhantomData,
            _irq_state,
        }
    }

    /// Splits a `RawWriteLockGuard` for different components of the backing data.
    pub fn map_split<U, V, F>(
        orig: Self,
        f: F,
    ) -> (RawWriteLockGuard<'a, U, I>, RawWriteLockGuard<'a, V, I>)
    where
        F: FnOnce(&mut T) -> (&mut U, &mut V),
    {
        // Ensure the original guard is never dropped
        let mut orig = ManuallyDrop::new(orig);

        // Move the original IRQ state out of drop.
        // SAFETY: we are really reading from a reference, so the source
        // pointer is safe. The original guard is behind `ManuallyDrop`,
        // so only the copy we just make will invoke drop.
        let _irq_state = unsafe { core::ptr::read(&orig._irq_state) };

        // Increase the writer count by 1.
        let rwlock = orig.rwlock;
        rwlock.fetch_add(compose_val(0, 1), Ordering::Release);

        let (a, b) = f(&mut *orig);
        (
            RawWriteLockGuard {
                rwlock,
                data: NonNull::from(a),
                _variance: PhantomData,
                _irq_state,
            },
            RawWriteLockGuard {
                rwlock,
                data: NonNull::from(b),
                _variance: PhantomData,
                // Acquire a second IRQ guard
                _irq_state: I::acquire_lock(),
            },
        )
    }
}

/// Implements the behavior of the [`WriteLockGuard`] when it is dropped
impl<T, I> Drop for RawWriteLockGuard<'_, T, I> {
    fn drop(&mut self) {
        self.rwlock.fetch_sub(compose_val(0, 1), Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`WriteLockGuard`] to
/// access the protected data.
impl<T, I> Deref for RawWriteLockGuard<'_, T, I> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the pointer is valid by construction and never changed.
        // The guard guarantees exclusive access.
        unsafe { self.data.as_ref() }
    }
}

/// Implements the behavior of dereferencing the [`WriteLockGuard`] to
/// access the protected data in a mutable way.
impl<T, I> DerefMut for RawWriteLockGuard<'_, T, I> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the pointer is valid by construction and never changed.
        // The guard guarantees exclusive access.
        unsafe { self.data.as_mut() }
    }
}

pub type WriteLockGuard<'a, T> = RawWriteLockGuard<'a, T, IrqUnsafeLocking>;
pub type WriteLockGuardIrqSafe<'a, T> = RawWriteLockGuard<'a, T, IrqGuardLocking>;
pub type WriteLockGuardAnyTpr<'a, T, const TPR: usize> =
    RawWriteLockGuard<'a, T, TprGuardLocking<TPR>>;

/// A simple Read-Write Lock (RWLock) that allows multiple readers or
/// one exclusive writer.
#[derive(Debug)]
pub struct RawRWLock<T, I> {
    /// An atomic 64-bit integer used for synchronization
    rwlock: AtomicU64,
    /// An UnsafeCell for interior mutability
    data: UnsafeCell<T>,
    /// Silence unused type warning
    phantom: PhantomData<fn(I)>,
}

// SAFETY: All well-formed locks are `Send`.
unsafe impl<T, I> Send for RawRWLock<T, I> {}
// SAFETY: All well-formed locks are `Sync`.
unsafe impl<T, I> Sync for RawRWLock<T, I> {}

const RW_BITS: u64 = 32;
const RW_MASK: u64 = (1 << RW_BITS) - 1;

/// Splits a 64-bit value into two parts: readers (low 32 bits) and
/// writers (high 32 bits).
///
/// # Parameters
///
/// - `val`: A 64-bit unsigned integer value to be split.
///
/// # Returns
///
/// A tuple containing two 32-bit unsigned integer values. The first
/// element of the tuple is the lower 32 bits of input value, and the
/// second is the upper 32 bits.
#[inline]
fn split_val(val: u64) -> (u64, u64) {
    (val & RW_MASK, val >> RW_BITS)
}

/// Composes a 64-bit value by combining the number of readers (low 32
/// bits) and writers (high 32 bits). This function is used to create a
/// 64-bit synchronization value that represents the current state of the
/// RWLock, including the count of readers and writers.
///
/// # Parameters
///
/// - `readers`: The number of readers (low 32 bits) currently holding read locks.
/// - `writers`: The number of writers (high 32 bits) currently holding write locks.
///
/// # Returns
///
/// A 64-bit value representing the combined state of readers and writers in the RWLock.
#[inline]
fn compose_val(readers: u64, writers: u64) -> u64 {
    (readers & 0xffff_ffffu64) | (writers << 32)
}

/// A reader-writer lock that allows multiple readers or a single writer
/// to access the protected data. [`RWLock`] provides exclusive access for
/// writers and shared access for readers, for efficient synchronization.
///
/// A lock can only be formed if the type it protects is `Send`, since the
/// contents of the lock will be sent to different threads.
impl<T: Send, I: IrqLocking> RawRWLock<T, I> {
    /// Creates a new [`RWLock`] instance with the provided initial data.
    ///
    /// # Parameters
    ///
    /// - `data`: The initial data to be protected by the [`RWLock`].
    ///
    /// # Returns
    ///
    /// A new [`RWLock`] instance with the specified initial data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use svsm::locking::RWLock;
    ///
    /// #[derive(Debug)]
    /// struct MyData {
    ///     value: i32,
    /// }
    ///
    /// let data = MyData { value: 42 };
    /// let rwlock = RWLock::new(data);
    /// ```
    pub const fn new(data: T) -> Self {
        Self {
            rwlock: AtomicU64::new(0),
            data: UnsafeCell::new(data),
            phantom: PhantomData,
        }
    }

    /// This function is used to wait until all writers have finished their
    /// operations and retrieve the current state of the [`RWLock`].
    ///
    /// # Returns
    ///
    /// A 64-bit value representing the current state of the [`RWLock`],
    /// including the count of readers and writers.
    #[inline]
    fn wait_for_writers(&self) -> u64 {
        loop {
            let val: u64 = self.rwlock.load(Ordering::Relaxed);
            let (_, writers) = split_val(val);

            if writers == 0 {
                return val;
            }
            core::hint::spin_loop();
        }
    }

    /// This function is used to wait until all readers have finished their
    /// operations and retrieve the current state of the [`RWLock`].
    ///
    /// # Returns
    ///
    /// A 64-bit value representing the current state of the [`RWLock`],
    /// including the count of readers and writers.
    #[inline]
    fn wait_for_readers(&self) -> u64 {
        loop {
            let val: u64 = self.rwlock.load(Ordering::Relaxed);
            let (readers, _) = split_val(val);

            if readers == 0 {
                return val;
            }
            core::hint::spin_loop();
        }
    }

    /// This function ensures exclusive access for a single writer and waits
    /// for all readers to finish before granting access to the writer.
    ///
    /// # Returns
    ///
    /// A [`WriteLockGuard`] that provides write access to the protected data.
    pub fn lock_write(&self) -> RawWriteLockGuard<'_, T, I> {
        let irq_state = I::acquire_lock();

        // Waiting for current writer to finish
        loop {
            let val = self.wait_for_writers();
            let (readers, _) = split_val(val);
            let new_val = compose_val(readers, 1);

            if self
                .rwlock
                .compare_exchange(val, new_val, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }

        // Now locked for write - wait until all readers finished
        let val: u64 = self.wait_for_readers();
        assert!(val == compose_val(0, 1));

        RawWriteLockGuard {
            rwlock: &self.rwlock,
            // SAFETY: the UnsafeCell is initialized on construction, so the
            // pointer can never be NULL
            data: unsafe { NonNull::new_unchecked(self.data.get()) },
            _variance: PhantomData,
            _irq_state: irq_state,
        }
    }

    /// Attempts to acquire the lock for writing without blocking. If the access
    /// could not be granted at this time, `None` is returned.
    pub fn try_lock_write(&self) -> Option<RawWriteLockGuard<'_, T, I>> {
        let irq_state = I::acquire_lock();

        let val = compose_val(0, 0);
        let new_val = compose_val(0, 1);
        self.rwlock
            .compare_exchange(val, new_val, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;

        Some(RawWriteLockGuard {
            rwlock: &self.rwlock,
            // SAFETY: the UnsafeCell is initialized on construction, so the
            // pointer can never be NULL
            data: unsafe { NonNull::new_unchecked(self.data.get()) },
            _variance: PhantomData,
            _irq_state: irq_state,
        })
    }

    /// Attempts to acquire the lock for writing in a single try, panicking
    /// if the operation would block.
    ///
    /// This is useful for per-CPU structures that use locks to detect
    /// reentrancy, ensuring that a deadlock instead produces an immediate
    /// panic.
    #[inline]
    pub fn write_noblock(&self) -> RawWriteLockGuard<'_, T, I> {
        self.try_lock_write().expect("Detected potential deadlock")
    }
}

/// A lock can only be acquired for read access if its inner type implements
/// `Sync` as well as `Send`.  This is because a read lock can be acquired
/// simultaneously by multiple threads, and therefore the data must be
/// shareable.
impl<T: Send + Sync, I: IrqLocking> RawRWLock<T, I> {
    /// This function allows multiple readers to access the data concurrently.
    ///
    /// # Returns
    ///
    /// A [`ReadLockGuard`] that provides read access to the protected data.
    pub fn lock_read(&self) -> RawReadLockGuard<'_, T, I> {
        let irq_state = I::acquire_lock();
        loop {
            let val = self.wait_for_writers();
            let (readers, _) = split_val(val);
            let new_val = compose_val(readers + 1, 0);

            if self
                .rwlock
                .compare_exchange(val, new_val, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }

        RawReadLockGuard {
            rwlock: &self.rwlock,
            // SAFETY: the UnsafeCell is initialized on construction, so the
            // pointer can never be NULL
            data: unsafe { NonNull::new_unchecked(self.data.get()) },
            _irq_state: irq_state,
        }
    }

    /// Attempts to acquire the lock for reading without blocking. If the access
    /// could not be granted at this time, `None` is returned.
    pub fn try_lock_read(&self) -> Option<RawReadLockGuard<'_, T, I>> {
        let irq_state = I::acquire_lock();

        // Attempt to update the reader count by 1. Bail if a writer is present.
        self.rwlock
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |val| {
                let (readers, writers) = split_val(val);
                (writers == 0).then(|| compose_val(readers + 1, 0))
            })
            .ok()?;

        Some(RawReadLockGuard {
            rwlock: &self.rwlock,
            // SAFETY: the UnsafeCell is initialized on construction, so the
            // pointer can never be NULL
            data: unsafe { NonNull::new_unchecked(self.data.get()) },
            _irq_state: irq_state,
        })
    }

    /// Attempts to acquire the lock for reading in a single try, panicking
    /// if the operation would block.
    ///
    /// This is useful for per-CPU structures that use locks to detect
    /// reentrancy, ensuring that a deadlock instead produces an immediate
    /// panic.
    #[inline]
    pub fn read_noblock(&self) -> RawReadLockGuard<'_, T, I> {
        self.try_lock_read().expect("Detected potential deadlock")
    }
}

pub type RWLock<T> = RawRWLock<T, IrqUnsafeLocking>;
pub type RWLockIrqSafe<T> = RawRWLock<T, IrqGuardLocking>;
pub type RWLockAnyTpr<T, const TPR: usize> = RawRWLock<T, TprGuardLocking<TPR>>;
pub type RWLockTpr<T> = RWLockAnyTpr<T, { TPR_LOCK }>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_rw() {
        let rwlock = RWLock::new(42);

        // Acquire a read lock and check the initial value
        let read_guard = rwlock.lock_read();
        assert_eq!(*read_guard, 42);

        drop(read_guard);

        let read_guard2 = rwlock.lock_read();
        assert_eq!(*read_guard2, 42);

        // Create another RWLock instance for modification
        let rwlock_modify = RWLock::new(0);

        let mut write_guard = rwlock_modify.lock_write();
        *write_guard = 99;
        assert_eq!(*write_guard, 99);

        drop(write_guard);

        let read_guard = rwlock.lock_read();
        assert_eq!(*read_guard, 42);
    }

    #[test]
    fn test_concurrent_readers() {
        // Let's test two concurrent readers on a new RWLock instance
        let rwlock_concurrent = RWLock::new(123);

        let read_guard1 = rwlock_concurrent.lock_read();
        let read_guard2 = rwlock_concurrent.lock_read();

        // Assert that both readers can access the same value (123)
        assert_eq!(*read_guard1, 123);
        assert_eq!(*read_guard2, 123);

        drop(read_guard1);
        drop(read_guard2);
    }

    /// Tests the expected behavior for `RWLock::try_lock_write()`.
    #[test]
    fn test_try_write() {
        let lock = RWLock::new(123);
        let mut write = lock.try_lock_write().unwrap();

        // Reads should fail unter writer is dropped
        assert!(lock.try_lock_read().is_none());
        *write = 321;
        drop(write);

        let read = lock.try_lock_read().unwrap();
        assert_eq!(*read, 321);
    }

    /// Tests the expected behavior for `RWLock::try_lock_read()`.
    #[test]
    fn test_try_read() {
        let lock = RWLock::new(123);
        let _read1 = lock.try_lock_read().unwrap();
        let _read2 = lock.try_lock_read().unwrap();

        // Writes should fail until all readers drop
        assert!(lock.try_lock_write().is_none());
        drop(_read1);
        assert!(lock.try_lock_write().is_none());
        drop(_read2);
        let _ = lock.try_lock_write().unwrap();
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Foo {
        bar: u32,
        baz: u32,
    }

    /// Tests the expected behavior for `RawReadLockGuard::map()`.
    #[test]
    fn test_read_map() {
        let lock = RWLock::new(Foo::default());

        let read = lock.try_lock_read().unwrap();
        let baz = RawReadLockGuard::map(read, |f| &f.baz);

        // Writes should fail, reads should still work
        assert!(lock.try_lock_write().is_none());
        let _ = lock.try_lock_read().unwrap();
        assert_eq!(*baz, 0);

        // After drop, reads and writes should work again
        drop(baz);
        let _ = lock.try_lock_write().unwrap();
        let _ = lock.try_lock_read().unwrap();
    }

    /// Tests the expected behavior for `RawWriteLockGuard::map()`.
    #[test]
    fn test_write_map() {
        let lock = RWLock::new(Foo::default());

        let mut write = lock.try_lock_write().unwrap();
        write.bar = 1;

        let mut baz = RawWriteLockGuard::map(write, |f| &mut f.baz);
        *baz = 2;

        // Reads and writes should still fail.
        assert!(lock.try_lock_write().is_none());
        assert!(lock.try_lock_read().is_none());

        // After drop, reads and writes should work again.
        drop(baz);
        let _ = lock.try_lock_write().unwrap();
        let read = lock.try_lock_read().unwrap();
        assert_eq!(read.bar, 1);
        assert_eq!(read.baz, 2);
    }

    /// Tests the expected behavior for `RawReadLockGuard::map_split()`.
    #[test]
    fn test_map_split_read() {
        let lock = RWLock::new(Foo::default());
        let read = lock.try_lock_read().unwrap();
        let (bar, baz) = RawReadLockGuard::map_split(read, |f| (&f.bar, &f.baz));

        // Reads should still succeed, writes should fail
        assert!(lock.try_lock_write().is_none());
        let _ = lock.try_lock_read().unwrap();

        // Even if one of the two guards drops, behavior should remain
        drop(bar);
        assert!(lock.try_lock_write().is_none());
        let _ = lock.try_lock_read().unwrap();

        // After both drops, reads and writes should work again.
        drop(baz);
        let _ = lock.try_lock_write().unwrap();
        let _ = lock.try_lock_read().unwrap();
    }

    /// Tests the expected behavior for `RawWriteLockGuard::map_split()`.
    #[test]
    fn test_map_split_write() {
        let lock = RWLock::new(Foo::default());
        let write = lock.try_lock_write().unwrap();
        let (mut bar, mut baz) = RawWriteLockGuard::map_split(write, |f| (&mut f.bar, &mut f.baz));

        // Reads and writes should fail
        assert!(lock.try_lock_read().is_none());
        assert!(lock.try_lock_write().is_none());

        // Even if one of the two guards drops, behavior should remain
        *bar = 1;
        drop(bar);
        assert!(lock.try_lock_read().is_none());
        assert!(lock.try_lock_write().is_none());

        // After both drops, reads and writes should work again.
        *baz = 2;
        drop(baz);
        let _ = lock.try_lock_write();
        let read = lock.try_lock_read().unwrap();
        assert_eq!(read.bar, 1);
        assert_eq!(read.baz, 2);
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn rw_lock_irq_unsafe() {
        use crate::cpu::irq_state::{raw_irqs_disable, raw_irqs_enable};
        use crate::cpu::irqs_enabled;

        let was_enabled = irqs_enabled();
        raw_irqs_enable();
        let lock = RWLock::new(0);

        // Lock for write
        let guard = lock.lock_write();
        // IRQs must still be enabled;
        assert!(irqs_enabled());
        // Unlock
        drop(guard);

        // Lock for read
        let guard = lock.lock_read();
        // IRQs must still be enabled;
        assert!(irqs_enabled());
        // Unlock
        drop(guard);

        // IRQs must still be enabled
        assert!(irqs_enabled());
        if !was_enabled {
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn rw_lock_irq_safe() {
        use crate::cpu::irq_state::{raw_irqs_disable, raw_irqs_enable};
        use crate::cpu::{irqs_disabled, irqs_enabled};

        let was_enabled = irqs_enabled();
        raw_irqs_enable();
        let lock = RWLockIrqSafe::new(0);

        // Lock for write
        let guard = lock.lock_write();
        // IRQs must be disabled
        assert!(irqs_disabled());
        // Unlock
        drop(guard);

        assert!(irqs_enabled());

        // Lock for read
        let guard = lock.lock_read();
        // IRQs must be disabled
        assert!(irqs_disabled());
        // Unlock
        drop(guard);

        // IRQs must still be enabled
        assert!(irqs_enabled());
        if !was_enabled {
            raw_irqs_disable();
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn rw_lock_tpr() {
        use crate::cpu::irq_state::raw_get_tpr;
        use crate::types::TPR_LOCK;

        assert_eq!(raw_get_tpr(), 0);
        let lock = RWLockTpr::new(0);

        // Lock for write
        let guard = lock.lock_write();
        // TPR must be raised
        assert_eq!(raw_get_tpr(), TPR_LOCK);
        // Unlock
        drop(guard);
        // TPR must be restored
        assert_eq!(raw_get_tpr(), 0);

        // Lock for read
        let guard = lock.lock_read();
        // TPR must be raised
        assert_eq!(raw_get_tpr(), TPR_LOCK);
        // Unlock
        drop(guard);
        // TPR must be restored
        assert_eq!(raw_get_tpr(), 0);
    }
}
