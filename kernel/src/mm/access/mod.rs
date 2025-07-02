// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

//! Memory mapping accesss module.
//!
//! This module contains abstractions to access virtual memory mappings
//! of various types (SVSM kernel-local, SVSM userspace, guest-shared,
//! hypervisor-shared).
//!
//! The module contains two types of mappings: [`OwnedMapping`] owns a
//! memory mappping, and unmaps the backing memory on drop.
//! [`BorrowedMapping`] does not drop any mappings, and has a lifetime
//! to indicate the validity of such mapping — this is typically the
//! lifetime of the [`OwnedMapping`] from which the borrow was acquired.
//!
//! Both mappings implement common interfaces through the following traits:
//!
//! * [`Mapping`]: common to all types, allows creating [`BorrowedMapping`]s
//!   from other mappings.
//! * [`ReadableMapping`]: allows reading the type behind a mapping, as long
//!   as it is [`Sized`] and [`FromBytes`].
//! * [`ReadableSliceMapping`]: equivalent for [`ReadableMapping`] for unsized
//!   types.
//! * [`WriteableMapping`]: allows writing a type to the backing memory of a
//!   mapping, as long as it is [`Sized`] and [`IntoBytes`].
//! * [`WriteableSliceMapping`]: equivalent for [`WriteableMapping`] for unsized
//!   types.
//! * [`RwMapping`]: supertrait including [`ReadableMapping`] and
//!   [`WriteableMapping`].
//! * [`RwSliceMapping`]: supertrait including [`ReadableSliceMapping`] and
//!   [`WriteableSliceMapping`].

extern crate alloc;

use crate::error::SvsmError;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::ops::Index;
use zerocopy::{FromBytes, IntoBytes};

mod guest;
mod local;
mod mapping;
mod shared;
mod user;

pub use guest::*;
pub use local::*;
pub use mapping::*;
pub use shared::*;
pub use user::*;

/// A low-level trait that implements a raw memory read.
pub trait MappingRead {
    /// # Safety
    ///
    /// See the safety considerations for [`core::ptr::copy`].
    unsafe fn read<T: FromBytes>(src: *const T, dst: *mut T, count: usize)
        -> Result<(), SvsmError>;
}

/// A low-level trait that implements a raw memory read.
pub trait MappingWrite {
    /// # Safety
    ///
    /// See the safety considerations for [`core::ptr::copy`].
    unsafe fn write<T: IntoBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError>;

    /// # Safety
    ///
    /// See the safety safety considerations for [`core::ptr::write_bytes`].
    unsafe fn write_bytes<T: IntoBytes>(
        dst: *mut T,
        count: usize,
        val: u8,
    ) -> Result<(), SvsmError>;
}

/// A trait implemented by all mapping types.
///
/// It allows reinterpreting the backing memory as a different type,
/// enabling flexibly working with raw memory in a type-safe manner.
pub trait Mapping<A, T: ?Sized> {
    fn borrow<U>(&self) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        self.borrow_at(0)
    }

    /// Borrows the given mapping as an instance of `U` located `byte_offset`
    /// bytes from the beginning of the current `T`.
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError>;

    fn borrow_slice<U>(&self, len: usize) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        self.borrow_slice_at(0, len)
    }

    /// Borrows the given mapping as a slice of `len` instances of `U`,
    /// located at `byte_offset` bytes from the beginning of the current `T`.
    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError>;
}

/// Blanket implementation for all immutable references to mappings.
impl<A, T, M> Mapping<A, T> for &M
where
    T: ?Sized,
    M: Mapping<A, T>,
{
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        M::borrow_at(self, byte_off)
    }

    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        M::borrow_slice_at(self, byte_off, len)
    }
}

/// Blanket implementation for all mutable references to mappings.
impl<A, T, M> Mapping<A, T> for &mut M
where
    T: ?Sized,
    M: Mapping<A, T>,
{
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        M::borrow_at(self, byte_off)
    }

    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        M::borrow_slice_at(self, byte_off, len)
    }
}

/// A trait implemented by all mappings which allow reading data through them.
pub trait ReadableMapping<A: MappingRead, T: FromBytes>: Mapping<A, T> {
    fn read(&self) -> Result<T, SvsmError>;
}

/// Blanket implementation for all immutable references to readable mappings.
impl<A, T, M> ReadableMapping<A, T> for &M
where
    A: MappingRead,
    T: FromBytes,
    M: ReadableMapping<A, T>,
{
    fn read(&self) -> Result<T, SvsmError> {
        M::read(self)
    }
}

/// Blanket implementation for all mutable references to readable mappings.
impl<A, T, M> ReadableMapping<A, T> for &mut M
where
    A: MappingRead,
    T: FromBytes,
    M: ReadableMapping<A, T>,
{
    fn read(&self) -> Result<T, SvsmError> {
        M::read(self)
    }
}

/// A trait implemented by all mappings which allow writing data through them.
pub trait WriteableMapping<A: MappingWrite, T: IntoBytes>: Mapping<A, T> {
    /// Writes the given value into the backing memory mapping.
    fn write<B: Borrow<T>>(&mut self, val: B) -> Result<(), SvsmError>;
}

/// Blanket implementation for all mutable references to writeable mappings.
impl<A, T, M> WriteableMapping<A, T> for &mut M
where
    A: MappingWrite,
    T: IntoBytes,
    M: WriteableMapping<A, T>,
{
    fn write<B: Borrow<T>>(&mut self, val: B) -> Result<(), SvsmError> {
        M::write(self, val)
    }
}

/// A trait implemented by mappings through which one may perform reads and
/// writes. It is automatically implemented for all mappings which already
/// implement [`ReadableMapping`] and [`WriteableMapping`].
pub trait RwMapping<A, T>: ReadableMapping<A, T> + WriteableMapping<A, T>
where
    A: MappingRead + MappingWrite,
    T: FromBytes + IntoBytes,
{
}

/// Blanket implementation for all implementors of [`ReadableMapping`]
/// and [`WriteableMapping`].
impl<A, T, M> RwMapping<A, T> for M
where
    A: MappingRead + MappingWrite,
    T: FromBytes + IntoBytes,
    M: ReadableMapping<A, T> + WriteableMapping<A, T>,
{
}

/// A trait implemented by all readable mappings over a slice of `T`.
pub trait ReadableSliceMapping<A, T>: Mapping<A, T>
where
    A: MappingRead,
    T: Index<usize> + ?Sized,
    T::Output: FromBytes + Sized,
{
    /// Reads the item at slice index `idx`.
    ///
    /// # Errors
    ///
    /// Other than due to memory access errors, this function will return an
    /// error if the index is out of bounds.
    fn read_item(&self, idx: usize) -> Result<T::Output, SvsmError>;

    /// Reads all the items in the backing slice into the provided buffer.
    ///
    /// # Errors
    ///
    /// Other than due to memory access errors, this function will return an
    /// error if the size of the given slice does not match that of the mapping.
    fn read_to(&self, dst: &mut [T::Output]) -> Result<(), SvsmError>;

    /// Reads the backing slice into a heap-allocated [`Vec`].
    fn read_to_vec(&self) -> Result<Vec<T::Output>, SvsmError>;
}

/// Blanket implementation for all immutable references to implementors of
/// [`ReadableSliceMapping`].
impl<A, T, M> ReadableSliceMapping<A, T> for &M
where
    A: MappingRead,
    T: Index<usize> + ?Sized,
    T::Output: FromBytes + Sized,
    M: ReadableSliceMapping<A, T>,
{
    fn read_item(&self, idx: usize) -> Result<T::Output, SvsmError> {
        M::read_item(self, idx)
    }

    fn read_to(&self, dst: &mut [T::Output]) -> Result<(), SvsmError> {
        M::read_to(self, dst)
    }

    fn read_to_vec(&self) -> Result<Vec<T::Output>, SvsmError> {
        M::read_to_vec(self)
    }
}

/// Blanket implementation for all mutable references to implementors of
/// [`ReadableSliceMapping`].
impl<A, T, M> ReadableSliceMapping<A, T> for &mut M
where
    A: MappingRead,
    T: Index<usize> + ?Sized,
    T::Output: FromBytes + Sized,
    M: ReadableSliceMapping<A, T>,
{
    fn read_item(&self, idx: usize) -> Result<T::Output, SvsmError> {
        M::read_item(self, idx)
    }

    fn read_to(&self, dst: &mut [T::Output]) -> Result<(), SvsmError> {
        M::read_to(self, dst)
    }

    fn read_to_vec(&self) -> Result<Vec<T::Output>, SvsmError> {
        M::read_to_vec(self)
    }
}

/// A trait implemented by all writeable mappings over a slice of `T`.
pub trait WriteableSliceMapping<A, T>: Mapping<A, T>
where
    A: MappingWrite,
    T: Index<usize> + ?Sized,
    T::Output: IntoBytes + Sized,
{
    /// Writes the given value at slice index `idx`. Returns an error if the
    /// index is out of bounds.
    ///
    /// # Errors
    ///
    /// Other than due to memory access errors, this function will return an
    /// error if the index is out of bounds.
    fn write_item<B: Borrow<T::Output>>(&mut self, val: B, idx: usize) -> Result<(), SvsmError>;

    /// Copies the given slice into the mapping.
    ///
    /// # Errors
    ///
    /// Other than due to memory access errors, this function will return an
    /// error if the size of the given slice does not match that of the mapping.
    fn write_from(&mut self, src: &[T::Output]) -> Result<(), SvsmError>;
}

/// Blanket implementation for all mutable references to implementors of
/// [`WriteableSliceMapping`].
impl<A, T, M> WriteableSliceMapping<A, T> for &mut M
where
    A: MappingWrite,
    T: Index<usize> + ?Sized,
    T::Output: IntoBytes + Sized,
    M: WriteableSliceMapping<A, T>,
{
    fn write_item<B: Borrow<T::Output>>(&mut self, val: B, idx: usize) -> Result<(), SvsmError> {
        M::write_item(self, val, idx)
    }

    fn write_from(&mut self, src: &[T::Output]) -> Result<(), SvsmError> {
        M::write_from(self, src)
    }
}

/// A trait implemented by mappings through which one may perform reads and
/// writes on slices. It is automatically implemented for all mappings which
/// already implement [`ReadableSliceMapping`] and [`WriteableSliceMapping`].
pub trait RwSliceMapping<A, T>: ReadableSliceMapping<A, T> + WriteableSliceMapping<A, T>
where
    A: MappingRead + MappingWrite,
    T: Index<usize> + ?Sized,
    T::Output: FromBytes + IntoBytes + Sized,
{
}

/// Blanket implementation for all implementors of [`ReadableSliceMapping`]
/// and [`WriteableSliceMapping`].
impl<A, T, M> RwSliceMapping<A, T> for M
where
    A: MappingRead + MappingWrite,
    T: Index<usize> + ?Sized,
    T::Output: FromBytes + IntoBytes + Sized,
    M: ReadableSliceMapping<A, T> + WriteableSliceMapping<A, T>,
{
}
