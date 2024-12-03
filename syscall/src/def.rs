// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use bitflags::bitflags;

// Syscall classes
const CLASS0: u64 = 0;
const CLASS1: u64 = 1 << 32;

// Syscall number in class0
pub const SYS_EXIT: u64 = CLASS0;
pub const SYS_EXEC: u64 = CLASS0 + 4;
pub const SYS_CLOSE: u64 = CLASS0 + 10;

// Syscall number in class1
pub const SYS_OPEN: u64 = CLASS1;
pub const SYS_READ: u64 = CLASS1 + 1;
pub const SYS_WRITE: u64 = CLASS1 + 2;
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

//
// Mode flags for Open system call
//
bitflags! {
    #[derive(Debug, Copy, Clone, Default)]
    pub struct FileModes: usize {
        /// Open file for reading
        const READ = 1 << 0;
        /// Open file for writing
        const WRITE = 1 << 1;
        /// Place file pointer at EOF
        const APPEND = 1 << 2;
        /// Truncate file to zero
        const TRUNC = 1 << 3;
    }
}

//
// File flags for Open system call
//
bitflags! {
    #[derive(Debug, Copy, Clone, Default)]
    pub struct FileFlags: usize {
        /// Create file if it does not exist
        const CREATE = 1 << 0;
    }
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
