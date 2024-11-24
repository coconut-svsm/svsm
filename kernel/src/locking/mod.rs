// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod common;
pub mod rwlock;
pub mod spinlock;

pub use common::{IrqGuardLocking, IrqLocking, TprGuardLocking};
pub use rwlock::{
    RWLock, RWLockAnyTpr, RWLockIrqSafe, RWLockTpr, ReadLockGuard, ReadLockGuardAnyTpr,
    ReadLockGuardIrqSafe, WriteLockGuard, WriteLockGuardAnyTpr, WriteLockGuardIrqSafe,
};
pub use spinlock::{
    LockGuard, LockGuardAnyTpr, LockGuardIrqSafe, RawLockGuard, SpinLock, SpinLockAnyTpr,
    SpinLockIrqSafe, SpinLockTpr,
};
