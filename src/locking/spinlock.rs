// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::cell::UnsafeCell;
use core::fmt::Debug;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct LockGuard<'a, T: Debug> {
    holder: &'a AtomicU64,
    data: &'a mut T,
}

impl<'a, T: Debug> Drop for LockGuard<'a, T> {
    fn drop(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

impl<'a, T: Debug> Deref for LockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: Debug> DerefMut for LockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

#[derive(Debug)]
pub struct SpinLock<T: Debug> {
    current: AtomicU64,
    holder: AtomicU64,
    data: UnsafeCell<T>,
}

unsafe impl<T: Debug> Sync for SpinLock<T> {}

impl<T: Debug> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            current: AtomicU64::new(0),
            holder: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
