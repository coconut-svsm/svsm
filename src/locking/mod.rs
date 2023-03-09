// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod rwlock;
pub mod spinlock;

pub use rwlock::{RWLock, ReadLockGuard, WriteLockGuard};
pub use spinlock::{LockGuard, SpinLock};
