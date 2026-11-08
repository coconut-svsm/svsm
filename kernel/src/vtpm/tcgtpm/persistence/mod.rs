// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Red Hat, Inc.

//! TPM persistence: manufacturing marker.

use crate::error::SvsmError;

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

    use crate::crt::TpmInode;
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
