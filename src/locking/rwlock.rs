// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::cell::UnsafeCell;
use core::fmt::Debug;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

/// A guard that provides read access to the data protected by [`RWLock`]
#[derive(Debug)]
#[must_use = "if unused the RWLock will immediately unlock"]
pub struct ReadLockGuard<'a, T: Debug> {
    /// Reference to the associated `AtomicU64` in the [`RWLock`]
    rwlock: &'a AtomicU64,
    /// Reference to the protected data
    data: &'a T,
}

/// Implements the behavior of the [`ReadLockGuard`] when it is dropped
impl<'a, T: Debug> Drop for ReadLockGuard<'a, T> {
    /// Release the read lock
    fn drop(&mut self) {
        self.rwlock.fetch_sub(1, Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`ReadLockGuard`] to
/// access the protected data.
impl<'a, T: Debug> Deref for ReadLockGuard<'a, T> {
    type Target = T;
    /// Allow reading the protected data through deref
    fn deref(&self) -> &T {
        self.data
    }
}

/// A guard that provides exclusive write access to the data protected by [`RWLock`]
#[derive(Debug)]
#[must_use = "if unused the RWLock will immediately unlock"]
pub struct WriteLockGuard<'a, T: Debug> {
    /// Reference to the associated `AtomicU64` in the [`RWLock`]
    rwlock: &'a AtomicU64,
    /// Reference to the protected data (mutable)
    data: &'a mut T,
}

/// Implements the behavior of the [`WriteLockGuard`] when it is dropped
impl<'a, T: Debug> Drop for WriteLockGuard<'a, T> {
    fn drop(&mut self) {
        // There are no readers - safe to just set lock to 0
        self.rwlock.store(0, Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`WriteLockGuard`] to
/// access the protected data.
impl<'a, T: Debug> Deref for WriteLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

/// Implements the behavior of dereferencing the [`WriteLockGuard`] to
/// access the protected data in a mutable way.
impl<'a, T: Debug> DerefMut for WriteLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

/// A simple Read-Write Lock (RWLock) that allows multiple readers or
/// one exclusive writer.
#[derive(Debug)]
pub struct RWLock<T: Debug> {
    /// An atomic 64-bit integer used for synchronization
    rwlock: AtomicU64,
    /// An UnsafeCell for interior mutability
    data: UnsafeCell<T>,
}

/// Implements the trait `Sync` for the [`RWLock`], allowing safe
/// concurrent access across threads.
unsafe impl<T: Debug> Sync for RWLock<T> {}

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
///
#[inline]
fn split_val(val: u64) -> (u64, u64) {
    (val & 0xffff_ffffu64, val >> 32)
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
///
#[inline]
fn compose_val(readers: u64, writers: u64) -> u64 {
    (readers & 0xffff_ffffu64) | (writers << 32)
}

/// A reader-writer lock that allows multiple readers or a single writer
/// to access the protected data. [`RWLock`] provides exclusive access for
/// writers and shared access for readers, for efficient synchronization.
///
impl<T: Debug> RWLock<T> {
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
        RWLock {
            rwlock: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// This function is used to wait until all writers have finished their
    /// operations and retrieve the current state of the [`RWLock`].
    ///
    /// # Returns
    ///
    /// A 64-bit value representing the current state of the [`RWLock`],
    /// including the count of readers and writers.
    ///
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
    ///
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

    /// This function allows multiple readers to access the data concurrently.
    ///
    /// # Returns
    ///
    /// A [`ReadLockGuard`] that provides read access to the protected data.
    ///
    pub fn lock_read(&self) -> ReadLockGuard<T> {
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

        ReadLockGuard {
            rwlock: &self.rwlock,
            data: unsafe { &*self.data.get() },
        }
    }

    /// This function ensures exclusive access for a single writer and waits
    /// for all readers to finish before granting access to the writer.
    ///
    /// # Returns
    ///
    /// A [`WriteLockGuard`] that provides write access to the protected data.
    ///
    pub fn lock_write(&self) -> WriteLockGuard<T> {
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

        WriteLockGuard {
            rwlock: &self.rwlock,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

mod tests {

    #[test]
    fn test_lock_rw() {
        use crate::locking::*;
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
        use crate::locking::*;
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
}
