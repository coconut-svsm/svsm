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
#[must_use = "if unused the RWLock will immediately unlock"]
pub struct ReadLockGuard<'a, T: Debug> {
    rwlock: &'a AtomicU64,
    data: &'a T,
}

impl<'a, T: Debug> Drop for ReadLockGuard<'a, T> {
    fn drop(&mut self) {
        self.rwlock.fetch_sub(1, Ordering::Release);
    }
}

impl<'a, T: Debug> Deref for ReadLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

#[derive(Debug)]
#[must_use = "if unused the RWLock will immediately unlock"]
pub struct WriteLockGuard<'a, T: Debug> {
    rwlock: &'a AtomicU64,
    data: &'a mut T,
}

impl<'a, T: Debug> Drop for WriteLockGuard<'a, T> {
    fn drop(&mut self) {
        // There are no readers - safe to just set lock to 0
        self.rwlock.store(0, Ordering::Release);
    }
}

impl<'a, T: Debug> Deref for WriteLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: Debug> DerefMut for WriteLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

#[derive(Debug)]
pub struct RWLock<T: Debug> {
    rwlock: AtomicU64,
    data: UnsafeCell<T>,
}

unsafe impl<T: Debug> Sync for RWLock<T> {}

#[inline]
fn split_val(val: u64) -> (u64, u64) {
    (val & 0xffff_ffffu64, val >> 32)
}

#[inline]
fn compose_val(readers: u64, writers: u64) -> u64 {
    (readers & 0xffff_ffffu64) | (writers << 32)
}

impl<T: Debug> RWLock<T> {
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
            core::hint::spin_loop();
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
            core::hint::spin_loop();
        }
    }

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

    /// Waits then locks the RWLock, returning a mutable pointer to the
    /// protected item. The lock must be released with a call to
    /// [`Self::unlock_write_direct()`] when access to the protected resource is
    /// no longer exclusively required.
    pub fn lock_write_direct(&self) -> *mut T {
        let guard = self.lock_write();
        core::mem::forget(guard);
        self.data.get()
    }

    /// Unlocks the RWLock, relinquishing access to the raw pointer
    /// that was gained by a previous call to [`Self::lock_write_direct()`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that the raw pointer returned by a
    /// previous call to [`Self::lock_write_direct()`] is not used after
    /// calling this function. Although the pointer may still point
    /// to a valid object there is no guarantee of this and use of
    /// the pointer is undefined behaviour.
    ///
    /// In order to gain mutable or immutable access to the object
    /// the caller must again restablish the RWLock.
    pub unsafe fn unlock_write_direct(&self) {
        // There are no readers - safe to just set lock to 0
        self.rwlock.store(0, Ordering::Release);
    }
}
