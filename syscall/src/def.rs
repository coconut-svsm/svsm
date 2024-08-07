// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

// SYSCALL numbers are not stable yet and just used for CPL-3 bringup

pub const SYS_EXIT: u64 = 1;

// Syscall error code number
pub const EINVAL: i32 = -1;
pub const ENOSYS: i32 = -2;
pub const ENOMEM: i32 = -3;
pub const EPERM: i32 = -4;
pub const EFAULT: i32 = -5;
pub const EBUSY: i32 = -6;
pub const ENOTFOUND: i32 = -7;
pub const ENOTSUPP: i32 = -8;
