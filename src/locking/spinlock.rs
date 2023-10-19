// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::cell::UnsafeCell;
use core::fmt::Debug;
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
pub struct LockGuard<'a, T: Debug> {
    holder: &'a AtomicU64,
    data: &'a mut T,
}

/// Implements the behavior of the [`LockGuard`] when it is dropped
impl<'a, T: Debug> Drop for LockGuard<'a, T> {
    /// Automatically releases the lock when the guard is dropped
    fn drop(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

/// Implements the behavior of dereferencing the [`LockGuard`] to
/// access the protected data.
impl<'a, T: Debug> Deref for LockGuard<'a, T> {
    type Target = T;
    /// Provides read-only access to the protected data
    fn deref(&self) -> &T {
        self.data
    }
}

/// Implements the behavior of dereferencing the [`LockGuard`] to
/// access the protected data in a mutable way.
impl<'a, T: Debug> DerefMut for LockGuard<'a, T> {
    /// Provides mutable access to the protected data
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

/// A simple spinlock implementation for protecting concurrent data access.
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
pub struct SpinLock<T: Debug> {
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
}

unsafe impl<T: Debug + Send> Send for SpinLock<T> {}
unsafe impl<T: Debug + Send> Sync for SpinLock<T> {}

impl<T: Debug> SpinLock<T> {
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
        SpinLock {
            current: AtomicU64::new(0),
            holder: AtomicU64::new(0),
            data: UnsafeCell::new(data),
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
    pub fn lock(&self) -> LockGuard<T> {
        let ticket = self.current.fetch_add(1, Ordering::Relaxed);
        loop {
            let h = self.holder.load(Ordering::Acquire);
            if h == ticket {
                break;
            }
            core::hint::spin_loop();
        }
        LockGuard {
            holder: &self.holder,
            data: unsafe { &mut *self.data.get() },
        }
    }

    /// This method tries to acquire the lock without blocking. If the
    /// lock is not available, it returns `None`. If the lock is
    /// successfully acquired, it returns a [`LockGuard`] that automatically
    /// releases the lock when it goes out of scope.
    pub fn try_lock(&self) -> Option<LockGuard<T>> {
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
                return Some(LockGuard {
                    holder: &self.holder,
                    data: unsafe { &mut *self.data.get() },
                });
            }
        }

        None
    }
}
