// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

use crate::{PackItError, PackItResult};
use core::mem::size_of_val;
#[cfg(feature = "std")]
use std::io::Write;
use zerocopy::byteorder::LittleEndian;
use zerocopy::{AsBytes, FromBytes, U16, U64};

#[derive(Clone, Copy, Debug, FromBytes, AsBytes)]
#[repr(C, packed)]
struct PackItFileHeaderPrelude {
    // TODO: make a repr(u16) enum out of this field with the
    // different types
    header_type: U16<LittleEndian>,
    name_len: U16<LittleEndian>,
    file_size: U64<LittleEndian>,
}

impl PackItFileHeaderPrelude {
    fn new(name: &str, data: &[u8]) -> PackItResult<Self> {
        let name_len = name
            .len()
            .try_into()
            .map_err(|_| PackItError::InvalidFileName)
            .map(U16::new)?;
        let file_size = U64::new(data.len() as u64);
        Ok(Self {
            header_type: U16::new(1),
            name_len,
            file_size,
        })
    }

    fn load(data: &[u8]) -> PackItResult<Self> {
        let prelude = Self::read_from_prefix(data).ok_or(PackItError::UnexpectedEOF)?;
        if prelude.header_type.get() != 1 {
            return Err(PackItError::InvalidFileHeader);
        }
        if prelude.name_len.get() == 0 {
            return Err(PackItError::InvalidFileHeader);
        }
        Ok(prelude)
    }

    #[cfg(feature = "std")]
    fn write<W: Write>(&self, dst: &mut W) -> PackItResult<()> {
        dst.write_all(self.as_bytes()).map_err(PackItError::IoError)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PackItFileHeader<'a> {
    prelude: PackItFileHeaderPrelude,
    name: &'a str,
}

impl<'a> PackItFileHeader<'a> {
    fn new(name: &'a str, data: &[u8]) -> PackItResult<Self> {
        let prelude = PackItFileHeaderPrelude::new(name, data)?;
        Ok(Self { prelude, name })
    }

    fn load(data: &'a [u8]) -> PackItResult<Self> {
        let prelude = PackItFileHeaderPrelude::load(data)?;

        let start = size_of_val(&prelude);
        let end = start
            .checked_add(prelude.name_len.into())
            .ok_or(PackItError::InvalidFileHeader)?;
        let raw_file_name = data.get(start..end).ok_or(PackItError::UnexpectedEOF)?;
        let name = core::str::from_utf8(raw_file_name).map_err(|_| PackItError::InvalidFileName)?;

        Ok(Self { prelude, name })
    }

    #[cfg(feature = "std")]
    fn write<W: Write>(&self, dst: &mut W) -> PackItResult<()> {
        self.prelude.write(dst)?;
        dst.write_all(self.name.as_bytes())
            .map_err(PackItError::IoError)
    }

    fn header_size(&self) -> usize {
        size_of_val(&self.prelude) + self.name.len()
    }

    fn file_size(&self) -> usize {
        self.prelude.file_size.get() as usize
    }
}

/// A file in an archive.
#[derive(Clone, Debug)]
pub struct PackItFile<'a> {
    hdr: PackItFileHeader<'a>,
    data: &'a [u8],
}

impl<'a> PackItFile<'a> {
    /// Create a new file with the given name and contents.
    pub fn new(name: &'a str, data: &'a [u8]) -> PackItResult<Self> {
        let hdr = PackItFileHeader::new(name, data)?;
        Ok(Self { hdr, data })
    }

    pub(crate) fn load(data: &'a [u8]) -> PackItResult<Self> {
        let hdr = PackItFileHeader::load(data)?;
        let start = hdr.header_size();
        let end = start
            .checked_add(hdr.file_size())
            .ok_or(PackItError::InvalidFileHeader)?;
        let data = data.get(start..end).ok_or(PackItError::UnexpectedEOF)?;
        Ok(Self { hdr, data })
    }

    #[cfg(feature = "std")]
    pub(crate) fn write<W: Write>(&self, dst: &mut W) -> PackItResult<()> {
        self.hdr.write(dst)?;
        dst.write_all(self.data).map_err(PackItError::IoError)
    }

    /// The name of the existing file
    pub const fn name(&self) -> &str {
        self.hdr.name
    }

    /// The file contents
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    /// The total size of the file in the archive, including the
    /// header and contents
    pub fn total_size(&self) -> usize {
        self.hdr.header_size() + self.hdr.file_size()
    }
}
