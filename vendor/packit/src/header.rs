// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

use crate::{PackItError, PackItResult};
use core::mem::size_of;
#[cfg(feature = "std")]
use std::io::Write;
use zerocopy::byteorder::LittleEndian;
use zerocopy::{AsBytes, FromBytes, U32};

/// Header Magic (PKIT)
pub const PACKIT_MAGIC: [u8; 4] = [0x50, 0x4b, 0x49, 0x54];

/// A PackIt archive header
#[derive(AsBytes, Clone, Copy, Debug, FromBytes)]
#[repr(C)]
pub struct PackItHeader {
    magic: [u8; 4],
    header_size: U32<LittleEndian>,
}

impl PackItHeader {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            magic: PACKIT_MAGIC,
            header_size: U32::new(size_of::<Self>() as u32),
        }
    }

    pub(crate) fn load(data: &[u8]) -> PackItResult<Self> {
        let header = Self::read_from_prefix(data).ok_or(PackItError::UnexpectedEOF)?;

        if header.magic != PACKIT_MAGIC {
            return Err(PackItError::InvalidHeader);
        }

        Ok(header)
    }

    #[cfg(feature = "std")]
    pub(crate) fn write<W: Write>(&self, dst: &mut W) -> PackItResult<()> {
        dst.write_all(self.as_bytes()).map_err(PackItError::IoError)
    }

    /// The size of the archive header
    pub fn header_size(&self) -> u32 {
        self.header_size.get()
    }
}

impl Default for PackItHeader {
    fn default() -> Self {
        Self::new()
    }
}
