// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use crate::fs::FsError;

pub trait Buffer {
    /// Copy data from the buffer into a slice
    ///
    /// # Arguments
    ///
    /// - `buf`: Destination slice for data.
    /// - `offset`: Offset into the buffer to start copying from.
    ///
    /// # Returns
    ///
    /// A `usize` representing the number of bytes copied on success, or
    /// [`SvsmError`] on failure. Not that the content of `buf` is undefined on
    /// failure.
    fn read_buffer(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError>;

    /// Copy data from a slice into the Buffer
    ///
    /// # Arguments
    ///
    /// - `buf`: Source slice for data.
    /// - `offset`: Offset into the buffer to start copying to.
    ///
    /// # Returns
    ///
    /// A `usize` representing the number of bytes copied on success, or
    /// [`SvsmError`] on failure.
    fn write_buffer(&mut self, _buf: &[u8], _offset: usize) -> Result<usize, SvsmError> {
        Err(SvsmError::FileSystem(FsError::not_supported()))
    }

    /// Total number of bytes represented by this buffer.
    ///
    /// # Returns
    ///
    /// Total number of bytes that can be copied from/to the buffer.
    fn size(&self) -> usize;
}
