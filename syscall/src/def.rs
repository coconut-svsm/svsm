// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

// Syscall classes
const CLASS0: u64 = 0;

// Syscall number in class0
pub const SYS_EXIT: u64 = CLASS0;

// Syscall error code number
pub const EINVAL: i32 = -1;
pub const ENOSYS: i32 = -2;
pub const ENOMEM: i32 = -3;
pub const EPERM: i32 = -4;
pub const EFAULT: i32 = -5;
pub const EBUSY: i32 = -6;
pub const ENOTFOUND: i32 = -7;
pub const ENOTSUPP: i32 = -8;
