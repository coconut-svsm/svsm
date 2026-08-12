// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Red Hat, Inc.

//! TPM persistence: manufacturing marker and C file I/O backend.

#[cfg(target_os = "none")]
pub mod cfile;

#[cfg(target_os = "none")]
pub use cfile::CFile;

use crate::error::SvsmError;

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
use inode::TpmInode;

pub trait Marker {
    fn exists() -> Result<bool, SvsmError> {
        Ok(false)
    }
    fn write() -> Result<(), SvsmError> {
        Ok(())
    }
    fn clear() -> Result<(), SvsmError> {
        Ok(())
    }
}

#[cfg(feature = "persistence")]
mod marker {
    extern crate alloc;

    use alloc::vec::Vec;
    use zeroize::Zeroizing;

    use crate::persistence::{
        Inode, persistence_available, persistence_read_inode_sync, persistence_write_inode_sync,
    };

    use super::*;

    const MANUFACTURED_MARKER: &[u8] = b"COCONUT-SVSM";

    pub struct ManufacturedMarker;

    impl Marker for ManufacturedMarker {
        fn exists() -> Result<bool, SvsmError> {
            if !persistence_available() {
                return Ok(false);
            }
            match persistence_read_inode_sync(TpmInode::Manufactured.inode())? {
                Some(data) => Ok(data.as_slice() == MANUFACTURED_MARKER),
                None => Ok(false),
            }
        }

        fn write() -> Result<(), SvsmError> {
            if !persistence_available() {
                return Ok(());
            }
            persistence_write_inode_sync(
                TpmInode::Manufactured.inode(),
                Zeroizing::new(MANUFACTURED_MARKER.to_vec()),
                true,
            )?;
            Ok(())
        }

        fn clear() -> Result<(), SvsmError> {
            if !persistence_available() {
                return Ok(());
            }
            persistence_write_inode_sync(
                TpmInode::Manufactured.inode(),
                Zeroizing::new(Vec::new()),
                true,
            )?;
            Ok(())
        }
    }
}

#[cfg(not(feature = "persistence"))]
mod marker {
    use super::*;

    pub struct ManufacturedMarker;

    impl Marker for ManufacturedMarker {}
}

pub use marker::ManufacturedMarker;
