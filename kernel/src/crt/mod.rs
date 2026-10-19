// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 IBM
// Copyright (c) 2026 Red Hat, Inc.

//! C runtime glue: `#[no_mangle]` wrappers that satisfy the `extern`
//! declarations in libcrt (malloc/free, serial_out, abort, file I/O).

#[cfg(target_os = "none")]
mod wrapper;

#[cfg(target_os = "none")]
pub mod cfile;

#[cfg(target_os = "none")]
pub use cfile::CFile;

#[cfg(feature = "persistence")]
mod inode {
    use crate::persistence::{Inode, InodeNamespace};

    #[derive(Clone, Copy, Debug)]
    #[repr(u32)]
    pub enum TpmInode {
        NvChip = 0,
        Manufactured = 1,
    }

    impl From<TpmInode> for u32 {
        fn from(val: TpmInode) -> u32 {
            val as u32
        }
    }

    impl Inode for TpmInode {
        const NAMESPACE: InodeNamespace = InodeNamespace::Tpm;
    }
}

#[cfg(feature = "persistence")]
pub use inode::TpmInode;
