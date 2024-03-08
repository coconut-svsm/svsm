// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

extern crate alloc;

#[cfg(feature = "std")]
use crate::PackItArchiveEncoder;
use crate::{PackItArchiveDecoder, PackItError, PackItFile, PackItHeader, PackItResult};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io::Write;

/// An structure describing a PackIt archive.
#[derive(Clone, Debug)]
pub struct PackItArchive<'a> {
    hdr: PackItHeader,
    files: Vec<PackItFile<'a>>,
}

impl<'a> PackItArchive<'a> {
    /// Create a new empty archive.
    pub fn new() -> Self {
        Self {
            hdr: PackItHeader::new(),
            files: Vec::new(),
        }
    }

    /// Create a a new empty archive with the specified header
    pub fn with_header(hdr: PackItHeader) -> Self {
        Self {
            hdr,
            files: Vec::new(),
        }
    }

    /// Get the archive header.
    pub fn header(&self) -> PackItHeader {
        self.hdr
    }

    /// Push a new file to the archive.
    pub fn insert(&mut self, file: PackItFile<'a>) {
        self.files.push(file);
    }

    /// Get the number of files in the archive
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the archive contains any files or not
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Encode the whole archive to the specified writer in one go.
    /// This uses a [`PackItArchiveEncoder`] under the hood.
    #[cfg(feature = "std")]
    pub fn write<W: Write>(&self, dst: &mut W) -> PackItResult<()> {
        let mut encoder = PackItArchiveEncoder::with_header(self.hdr, dst)?;
        for file in self.files.iter() {
            encoder.write_file(file)?;
        }
        dst.flush()?;
        Ok(())
    }
}

impl<'a> TryFrom<PackItArchiveDecoder<'a>> for PackItArchive<'a> {
    type Error = PackItError;

    /// Create a new in-memory archive from a lazy decoder.
    fn try_from(decoder: PackItArchiveDecoder<'a>) -> PackItResult<Self> {
        let files = decoder.collect::<PackItResult<Vec<_>>>()?;
        Ok(Self {
            hdr: decoder.header(),
            files,
        })
    }
}

impl Default for PackItArchive<'_> {
    fn default() -> Self {
        Self::new()
    }
}
