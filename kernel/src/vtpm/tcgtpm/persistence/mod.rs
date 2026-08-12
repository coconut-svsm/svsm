// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Red Hat, Inc.

//! TPM persistence: manufacturing marker and C file I/O backend.

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

#[cfg(all(feature = "persistence", target_os = "none"))]
use inode::TpmInode;
