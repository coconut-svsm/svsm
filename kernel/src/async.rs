// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of Rust `async` [`Future`](core::future::Future) related functionality.

use cocoon_tpm_utils_async as utils_async;

use core::{ptr, task};
use utils_async::sync_types;

use crate::locking::{LockGuard, RWLock, ReadLockGuard, SpinLock, WriteLockGuard};

impl<T: Send> sync_types::Lock<T> for SpinLock<T> {
    type Guard<'a>
        = LockGuard<'a, T>
    where
        T: 'a;

    fn lock(&self) -> Self::Guard<'_> {
        SpinLock::lock(self)
    }
}

impl<T: Send> sync_types::ConstructibleLock<T> for SpinLock<T> {
    fn get_mut(&mut self) -> &mut T {
        SpinLock::get_mut(self)
    }
}

impl<T: Send + Sync> sync_types::RwLock<T> for RWLock<T> {
    type ReadGuard<'a>
        = ReadLockGuard<'a, T>
    where
        T: 'a;
    type WriteGuard<'a>
        = WriteLockGuard<'a, T>
    where
        T: 'a;

    fn read(&self) -> Self::ReadGuard<'_> {
        RWLock::lock_read(self)
    }

    fn write(&self) -> Self::WriteGuard<'_> {
        RWLock::lock_write(self)
    }

    fn get_mut(&mut self) -> &mut T {
        RWLock::get_mut(self)
    }
}

/// Implementation of the `cocoon-tpm-utils-async` crate's [`SyncTypes`](sync_types::SyncTypes)
/// trait suitable for the SVSM kernel execution environment.
#[derive(Debug)]
pub struct SvsmSyncTypes;

impl sync_types::SyncTypes for SvsmSyncTypes {
    type Lock<T: Send> = SpinLock<T>;
    type RwLock<T: Send + Sync> = RWLock<T>;
    type SyncRcPtrFactory = sync_types::GenericArcFactory;
}

/// Instantiate a nop [`RawWaker`](task::RawWaker), which simply ignores any wakeups.
fn nop_raw_waker_new() -> task::RawWaker {
    // No resources are associated with a nop waker, pass null for the data pointer.
    task::RawWaker::new(ptr::null(), &NOP_WAKER_VTABLE)
}

/// [`RawWakerVTable`](task::RawWakerVTable) for a nop waker instantiated through [`nop_raw_waker_new()`].
const NOP_WAKER_VTABLE: task::RawWakerVTable = task::RawWakerVTable::new(
    nop_raw_waker_clone,
    nop_raw_waker_wake,
    nop_raw_waker_wake_by_ref,
    nop_raw_waker_drop,
);

/// `clone()` entry of the [`NOP_WAKER_VTABLE`].
// SAFETY: The RawWakerVTable signature requires the function to be marked unsafe, there's nothing
// actually unsafe about it -- data is always a null ptr and not accessed.
unsafe fn nop_raw_waker_clone(data: *const ()) -> task::RawWaker {
    // No ressources are associated with the nop waker.
    debug_assert!(data.is_null());
    task::RawWaker::new(ptr::null(), &NOP_WAKER_VTABLE)
}

/// `drop()` entry of the [`NOP_WAKER_VTABLE`].
// SAFETY: The RawWakerVTable signature requires the function to be marked unsafe, there's nothing
// actually unsafe about it -- data is always a null ptr and not accessed.
unsafe fn nop_raw_waker_drop(data: *const ()) {
    // No ressources are associated with the nop waker.
    debug_assert!(data.is_null());
}

/// `wake()` entry of the [`NOP_WAKER_VTABLE`].
// SAFETY: The RawWakerVTable signature requires the function to be marked unsafe, there's nothing
// actually unsafe about it -- data is always a null ptr and not accessed.
unsafe fn nop_raw_waker_wake(data: *const ()) {
    // Do nothing -- it's a nop waker. No ressources are associated with it.
    debug_assert!(data.is_null());
}

/// `wake_by_ref()` entry of the [`NOP_WAKER_VTABLE`].
// SAFETY: The RawWakerVTable signature requires the function to be marked unsafe, there's nothing
// actually unsafe about it -- data is always a null ptr and not accessed.
unsafe fn nop_raw_waker_wake_by_ref(_data: *const ()) {
    // Do nothing -- it's a nop waker.
}

/// Busypoll an asynchronous task to completion.
///
/// The task to poll on is represented as a closure, `task`. Note that this
/// scheme enables convenient polling on standard Rust [`Future`](core::future::Future)s,
/// as well as on `Future`-like types taking additional arguments for their `poll()`.
///
/// # Arguments:
///
/// * `task` -> The task to poll to completion.
pub fn task_busypoll_to_completion<O, T: FnMut(&mut task::Context<'_>) -> task::Poll<O>>(
    mut task: T,
) -> O {
    let raw_waker = nop_raw_waker_new();
    // SAFETY: the RawWaker and RawWakerVTable contracts are trivially upheld.
    let waker = unsafe { task::Waker::from_raw(raw_waker) };
    let mut ctx = task::Context::from_waker(&waker);

    loop {
        if let task::Poll::Ready(result) = task(&mut ctx) {
            return result;
        }
    }
}
