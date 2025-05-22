// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

/// A lock guard obtained from a [`SpinLock`]. This lock guard
/// provides exclusive access to the data protected by a [`SpinLock`],
/// ensuring that the lock is released when it goes out of scope.
///
/// # Examples
///
/// ```
/// use userlib::SpinLock;
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
pub struct LockGuard<'a, T> {
    holder: &'a AtomicU64,
    data: &'a mut T,
}

impl<T> Drop for LockGuard<'_, T> {
    fn drop(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

impl<T> Deref for LockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<T> DerefMut for LockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

#[derive(Debug)]
pub struct SpinLock<T> {
    current: AtomicU64,
    holder: AtomicU64,
    data: UnsafeCell<T>,
}

// SAFETY: SpinLock guarantees mutually exclusive access to wrapped data.
unsafe impl<T> Sync for SpinLock<T> {}

impl<'a, T> SpinLock<T> {
    /// Create a new `SpinLock`
    ///
    /// # Arguments:
    ///
    /// * `data`: Data to be protected by the `SpinLock`. The data is moved into
    ///   and from this point on owned by the SpinLock.
    ///
    /// # Returns:
    ///
    /// New instance of `SpinLock` containing `data`.
    pub const fn new(data: T) -> Self {
        SpinLock {
            current: AtomicU64::new(0),
            holder: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Takes lock and returns [`LockGuard`] which gives exclusive access to
    /// the protected data.
    ///
    /// # Returns:
    ///
    /// Instance of [`LockGuard`] to exclusivly access the data a release the
    /// lock when it goes out of scope.
    pub fn lock(&'a self) -> LockGuard<'a, T> {
        let ticket = self.current.fetch_add(1, Ordering::Relaxed);
        loop {
            let h = self.holder.load(Ordering::Acquire);
            if h == ticket {
                break;
            }
        }

        LockGuard {
            holder: &self.holder,
            // SAFETY: Safe because at this point the lock is held and this is
            // guaranteed to be the only reference.
            data: unsafe { &mut *self.data.get() },
        }
    }
}
