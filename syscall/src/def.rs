// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

// Syscall classes
const CLASS0: u64 = 0;
const CLASS1: u64 = 1 << 32;

// Syscall number in class0
pub const SYS_EXIT: u64 = CLASS0;
pub const SYS_EXEC: u64 = CLASS0 + 4;
pub const SYS_CLOSE: u64 = CLASS0 + 10;

// Syscall number in class1
pub const SYS_OPENDIR: u64 = CLASS1 + 4;
pub const SYS_READDIR: u64 = CLASS1 + 5;

// Syscall error code number
pub const EINVAL: i32 = -1;
pub const ENOSYS: i32 = -2;
pub const ENOMEM: i32 = -3;
pub const EPERM: i32 = -4;
pub const EFAULT: i32 = -5;
pub const EBUSY: i32 = -6;
pub const ENOTFOUND: i32 = -7;
pub const ENOTSUPP: i32 = -8;

/// Maximum length of file name in bytes
pub const F_NAME_SIZE: usize = 256;

/// Files
pub const F_TYPE_FILE: u8 = 0;

/// Directories
pub const F_TYPE_DIR: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DirEnt {
    /// Entry name
    pub file_name: [u8; F_NAME_SIZE],
    /// Entry type
    pub file_type: u8,
    /// File size - 0 for directories
    pub file_size: u64,
}

impl Default for DirEnt {
    fn default() -> Self {
        DirEnt {
            file_name: [0; F_NAME_SIZE],
            file_type: 0,
            file_size: 0,
        }
    }
}
