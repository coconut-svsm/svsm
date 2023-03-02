// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use core::sync::atomic::{AtomicU64, Ordering};
use core::ops::{Deref, DerefMut};
use core::cell::UnsafeCell;

pub struct ReadLockGuard<'a, T> {
    rwlock: &'a AtomicU64,
    data: &'a mut T,
}

impl<'a, T> Drop for ReadLockGuard<'a, T> {
    fn drop(&mut self) {
        self.rwlock.fetch_sub(1, Ordering::Release);
    }
}

impl<'a, T> Deref for ReadLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

pub struct WriteLockGuard<'a, T> {
    rwlock: &'a AtomicU64,
    data: &'a mut T,
}

impl<'a, T> Drop for WriteLockGuard<'a, T> {
    fn drop(&mut self) {
        // There are no readers - safe to just set lock to 0
        self.rwlock.store(0, Ordering::Release);
    }
}

impl<'a, T> Deref for WriteLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T> DerefMut for WriteLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

pub struct RWLock<T> {
    rwlock: AtomicU64,
    data: UnsafeCell<T>,
}

unsafe impl<T> Sync for RWLock<T> {}

#[inline]
fn split_val(val: u64) -> (u64, u64) {
    (val & 0xffff_ffffu64, val >> 32)
}

#[inline]
fn compose_val(readers: u64, writers: u64) -> u64 {
    (readers & 0xffff_ffffu64) | (writers << 32)
}

impl<T> RWLock<T> {
    pub const fn new(data: T) -> Self {
        RWLock {
            rwlock: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

    #[inline]
    fn wait_for_writers(&self) -> u64 {
        loop {
            let val: u64 = self.rwlock.load(Ordering::Relaxed);
            let (_, writers) = split_val(val);

            if writers == 0 {
                return val;
            }
        }
    }

    #[inline]
    fn wait_for_readers(&self) -> u64 {
        loop {
            let val: u64 = self.rwlock.load(Ordering::Relaxed);
            let (readers, _) = split_val(val);

            if readers == 0 {
                return val;
            }
        }
    }

    pub fn lock_read(&self) -> ReadLockGuard<T> {
        loop {
            let val = self.wait_for_writers();
            let (readers, _) = split_val(val);
            let new_val = compose_val(readers + 1, 0);

            if self.rwlock.compare_exchange(val, new_val, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
        }

        ReadLockGuard {
            rwlock: &self.rwlock,
            data: unsafe { &mut *self.data.get() },
        }
    }

    pub fn lock_write(&self) -> WriteLockGuard<T> {
        // Waiting for current writer to finish
        loop {
            let val = self.wait_for_writers();
            let (readers, _) = split_val(val);
            let new_val = compose_val(readers, 1);

            if self.rwlock.compare_exchange(val, new_val, Ordering::Acquire, Ordering::Relaxed) .is_ok() {
                break;
            }
        }

        // Now locked for write - wait until all readers finished
        let val: u64 = self.wait_for_readers();
        assert!(val == compose_val(0,1));

        WriteLockGuard {
            rwlock: &self.rwlock,
            data: unsafe { &mut *self.data.get() },
        }
    }
}
