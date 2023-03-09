// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub mod rwlock;
pub mod spinlock;

pub use rwlock::{RWLock, ReadLockGuard, WriteLockGuard};
pub use spinlock::{LockGuard, SpinLock};
