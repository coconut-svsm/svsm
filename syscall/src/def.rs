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
pub const SYS_CLOSE: u64 = CLASS0 + 10;

// Syscall number in class1
pub const SYS_OPENDIR: u64 = CLASS1 + 4;
pub const SYS_READDIR: u64 = CLASS1 + 5;

///Maximum length of path name including null character in bytes
pub const PATH_MAX: usize = 4096;

/// Maximum length of file name in bytes
pub const F_NAME_SIZE: usize = 256;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DirEnt {
    /// Entry name
    pub file_name: [u8; F_NAME_SIZE],
    /// Entry type
    pub file_type: FileType,
    /// File size - 0 for directories
    pub file_size: u64,
}

impl Default for DirEnt {
    fn default() -> Self {
        DirEnt {
            file_name: [0; F_NAME_SIZE],
            file_type: FileType::File,
            file_size: 0,
        }
    }
}
