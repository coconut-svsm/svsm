// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of Rust `async` [`Future`] related functionality.

use cocoon_tpm_utils_async as utils_async;

use core::task;
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

/// Busypoll an asynchronous task to completion.
///
/// The task to poll on is represented as a closure, `task`. Note that this scheme enables
/// convenient polling on standard Rust [`Future`]s, as well as on `Future`-like types taking
/// additional arguments for their `poll()`.
///
/// # Arguments:
///
/// * `task` -> The task to poll to completion.
pub fn task_busypoll_to_completion<O, T: FnMut(&mut task::Context<'_>) -> task::Poll<O>>(
    mut task: T,
) -> O {
    let mut ctx = task::Context::from_waker(task::Waker::noop());
    loop {
        if let task::Poll::Ready(result) = task(&mut ctx) {
            return result;
        }
    }
}
