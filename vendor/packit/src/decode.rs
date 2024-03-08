// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

use crate::{PackItFile, PackItHeader, PackItResult};

/// A lazy raw PackIt archive decoder.
#[derive(Clone, Copy, Debug)]
pub struct PackItArchiveDecoder<'a> {
    hdr: PackItHeader,
    raw_data: &'a [u8],
    current: usize,
}

impl<'a> PackItArchiveDecoder<'a> {
    /// The archive header
    pub fn header(&self) -> PackItHeader {
        self.hdr
    }

    /// Load an archive from an existing blob
    pub fn load(raw_data: &'a [u8]) -> PackItResult<Self> {
        let hdr = PackItHeader::load(raw_data)?;
        Ok(Self {
            hdr,
            raw_data,
            current: hdr.header_size() as usize,
        })
    }
}

/// Iterate over packed [`PackItFile`] files.
impl<'a> core::iter::Iterator for PackItArchiveDecoder<'a> {
    type Item = PackItResult<PackItFile<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let data = self
            .raw_data
            .get(self.current..)
            .filter(|d| !d.is_empty())?;

        match PackItFile::load(data) {
            Ok(f) => {
                self.current += f.total_size();
                Some(Ok(f))
            }
            Err(e) => {
                // Stop iterating
                self.current = self.raw_data.len() + 1;
                Some(Err(e))
            }
        }
    }
}
