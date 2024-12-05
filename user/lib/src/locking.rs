// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

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
    pub const fn new(data: T) -> Self {
        SpinLock {
            current: AtomicU64::new(0),
            holder: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

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
