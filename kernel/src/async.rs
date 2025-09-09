// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of Rust `async` [`Future`](core::future::Future) related functionality.

use cocoon_tpm_utils_async as utils_async;

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
