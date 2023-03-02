// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

pub struct LockGuard<'a, T> {
    holder: &'a AtomicU64,
    data: &'a mut T,
}

impl<'a, T> Drop for LockGuard<'a, T> {
    fn drop(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

pub struct SpinLock<T> {
    current: AtomicU64,
    holder: AtomicU64,
    data: UnsafeCell<T>,
}

unsafe impl<T> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
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

    pub fn try_lock(&self) -> Result<LockGuard<T>, ()> {
        let current = self.current.load(Ordering::Relaxed);
        let holder = self.holder.load(Ordering::Acquire);

        if current == holder {
            let result = self.current.compare_exchange(current, current + 1,
                                                       Ordering::Acquire, Ordering::Relaxed);
            if let Ok(_) = result {
                return Ok(LockGuard {
                                holder: &self.holder,
                                data: unsafe { &mut *self.data.get() },
                            });
            }
        }

        Err(())
    }

    pub fn unlock(&mut self) {
        self.holder.fetch_add(1, Ordering::Release);
    }
}

impl<'a, T> Deref for LockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T> DerefMut for LockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}
