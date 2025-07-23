// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::fs::FsError;
use crate::mm::access::{
    BorrowedMapping, Mapping, ReadableSliceMapping, User, WriteableSliceMapping,
};
use core::cmp;

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

/// Struct to add a [`Buffer`] interface to a mutable `&[u8]` slice
#[derive(Debug)]
pub struct SliceMutRefBuffer<'a> {
    slice: &'a mut [u8],
}

impl<'a> SliceMutRefBuffer<'a> {
    pub fn new(slice: &'a mut [u8]) -> Self {
        Self { slice }
    }
}

impl Buffer for SliceMutRefBuffer<'_> {
    fn read_buffer(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        let size = cmp::min(buf.len(), self.slice.len() - offset);
        buf[..size].clone_from_slice(&self.slice[offset..offset + size]);
        Ok(size)
    }

    fn write_buffer(&mut self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        let size = cmp::min(buf.len(), self.slice.len() - offset);
        self.slice[offset..offset + size].clone_from_slice(&buf[..size]);
        Ok(size)
    }

    fn size(&self) -> usize {
        self.slice.len()
    }
}

#[derive(Debug)]
/// Struct to add a [`Buffer`] interface to a non-mutable `&[u8]` slice
pub struct SliceRefBuffer<'a> {
    slice: &'a [u8],
}

impl<'a> SliceRefBuffer<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice }
    }
}

impl Buffer for SliceRefBuffer<'_> {
    fn read_buffer(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        let size = cmp::min(buf.len(), self.slice.len() - offset);
        buf[..size].clone_from_slice(&self.slice[offset..offset + size]);
        Ok(size)
    }

    fn size(&self) -> usize {
        self.slice.len()
    }
}

#[derive(Debug)]
pub struct UserBuffer {
    // Userspace memory is always mapped in the same virtual range,
    // so `'static` is correct.
    mem: BorrowedMapping<'static, User, [u8]>,
}

impl UserBuffer {
    pub fn new(addr: VirtAddr, size: usize) -> Result<Self, SvsmError> {
        let mem = BorrowedMapping::user_slice_from_address(addr, size)?;
        Ok(Self { mem })
    }
}

impl Buffer for UserBuffer {
    fn read_buffer(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        let size = cmp::min(buf.len(), self.mem.len().checked_sub(offset).unwrap());
        if size > 0 {
            self.mem
                .borrow_slice_at(offset, size)?
                .read_to(&mut buf[..size])?;
        }
        Ok(size)
    }

    fn write_buffer(&mut self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        let size = cmp::min(buf.len(), self.mem.len().checked_sub(offset).unwrap());
        if size > 0 {
            self.mem
                .borrow_slice_at(offset, size)?
                .write_from(&buf[..size])?;
        }
        Ok(size)
    }

    fn size(&self) -> usize {
        self.mem.len()
    }
}
