// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod common;
pub mod rwlock;
pub mod spinlock;

pub use common::{IrqLocking, IrqSafeLocking, IrqUnsafeLocking};
pub use rwlock::{
    RWLock, RWLockIrqSafe, ReadLockGuard, ReadLockGuardIrqSafe, WriteLockGuard,
    WriteLockGuardIrqSafe,
};
pub use spinlock::{LockGuard, LockGuardIrqSafe, RawLockGuard, SpinLock, SpinLockIrqSafe};
