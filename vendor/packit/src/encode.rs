// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

use crate::{PackItFile, PackItHeader, PackItResult};
use std::io::Write;

/// A lazy PackIt archive encoder.
pub struct PackItArchiveEncoder<'a, W> {
    hdr: PackItHeader,
    writer: &'a mut W,
}

impl<'a, W: Write> PackItArchiveEncoder<'a, W> {
    /// Create a new encoder with the default header
    pub fn new(writer: &'a mut W) -> PackItResult<Self> {
        let hdr = PackItHeader::new();
        Self::with_header(hdr, writer)
    }

    /// Create a a new encoder with the specified header
    pub fn with_header(hdr: PackItHeader, writer: &'a mut W) -> PackItResult<Self> {
        hdr.write(writer)?;
        Ok(Self { hdr, writer })
    }

    /// Get the archive header
    pub fn header(&self) -> PackItHeader {
        self.hdr
    }

    /// Write a single file to the archive
    pub fn write_file(&mut self, file: &PackItFile<'_>) -> PackItResult<()> {
        file.write(self.writer)
    }
}
