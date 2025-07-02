// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use super::{BorrowedMapping, MappingRead, MappingWrite, OwnedMapping};
use crate::address::PhysAddr;
use crate::cpu::mem::{unsafe_copy_bytes, write_bytes};
use crate::error::SvsmError;
use zerocopy::{FromBytes, IntoBytes};

/// An empty structure to indicate access to local SVSM memory.
#[derive(Debug, Clone, Copy)]
pub struct Local;

impl MappingRead for Local {
    unsafe fn read<T: FromBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        // SAFETY: safety requirements must be upheld by the caller
        unsafe { unsafe_copy_bytes(src, dst, count) };
        Ok(())
    }
}

impl MappingWrite for Local {
    unsafe fn write<T: IntoBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        // SAFETY: safety requirements must be upheld by the caller
        unsafe { unsafe_copy_bytes(src, dst, count) };
        Ok(())
    }

    unsafe fn write_bytes<T: IntoBytes>(
        dst: *mut T,
        count: usize,
        val: u8,
    ) -> Result<(), SvsmError> {
        // SAFETY: safety requirements must be upheld by the caller
        unsafe { write_bytes(dst, count, val) };
        Ok(())
    }
}

impl<T> OwnedMapping<Local, T> {
    /// # Safety
    ///
    /// The caller must ensure that the physical memory region starting
    /// at the given physical address (and extending for as many pages as
    /// required to hold `T`) is not accesible outside the SVSM kernel.
    pub unsafe fn map_local(paddr: PhysAddr) -> Result<Self, SvsmError> {
        // SAFETY: the caller must uphold the safety requirements
        Self::map::<false>(paddr)
    }

    /// # Safety
    ///
    /// The caller must ensure that the physical memory region starting
    /// at the given physical address (and extending for as many pages as
    /// required to hold `len` instances of T`) is not accesible outside
    /// the SVSM kernel.
    pub unsafe fn map_local_slice(
        paddr: PhysAddr,
        len: usize,
    ) -> Result<OwnedMapping<Local, [T]>, SvsmError> {
        Self::map_slice::<false>(paddr, len)
    }
}

impl<T: FromBytes> OwnedMapping<Local, T> {
    /// Gets a reference to the underlying `T`. This method is only available
    /// for SVSM-local mappings.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the referenced memory is not mutably aliased
    /// anywhere else in the code.
    pub unsafe fn as_ref(&self) -> &T {
        // SAFETY: this type ensures that memory stays mapped and that the
        // accessed virtual addresses are properly aligned. The caller must
        // guarantee the rest of the safety requirements.
        unsafe { &*self.as_ptr::<T>() }
    }
}

impl<T: FromBytes> OwnedMapping<Local, [T]> {
    /// # Safety
    ///
    /// The caller must ensure that the referenced memory is not mutably aliased
    /// anywhere else in the code.
    pub unsafe fn as_slice(&self) -> &[T] {
        // SAFETY: this type ensures that memory stays mapped and that the
        // accessed virtual addresses are properly aligned. The caller must
        // guarantee the rest of the safety requirements.
        unsafe { core::slice::from_raw_parts(self.as_ptr::<T>(), self.len()) }
    }
}

impl<T: FromBytes + IntoBytes> OwnedMapping<Local, [T]> {
    /// # Safety
    ///
    /// The caller must ensure that the referenced memory is not aliased
    /// (mutably or immutably) anywhere else.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: this type ensures that memory stays mapped and that the
        // accessed virtual addresses are properly aligned. The caller must
        // guarantee the rest of the safety requirements.
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr::<T>(), self.len()) }
    }
}

impl<T: FromBytes> BorrowedMapping<'_, Local, T> {
    /// Gets a reference to the underlying `T`. This method is only available
    /// for SVSM-local mappings.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the referenced memory is not mutably aliased
    /// anywhere else in the code.
    pub unsafe fn as_ref(&self) -> &T {
        // SAFETY: this type ensures that memory stays mapped and that the
        // accessed virtual addresses are properly aligned. The caller must
        // guarantee the rest of the safety requirements.
        unsafe { &*self.as_ptr::<T>() }
    }
}

impl<T: FromBytes> BorrowedMapping<'_, Local, [T]> {
    /// Returns an immutable slice to the underlying memory. This method is only
    /// available for SVSM-local mappings.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the referenced memory is not mutably aliased
    /// anywhere else in the code.
    pub unsafe fn as_slice(&self) -> &[T] {
        // SAFETY: this type ensures that memory stays mapped and that the
        // accessed virtual addresses are properly aligned. The caller must
        // guarantee the rest of the safety requirements.
        unsafe { core::slice::from_raw_parts(self.as_ptr::<T>(), self.len()) }
    }
}

impl<T: FromBytes + IntoBytes> BorrowedMapping<'_, Local, [T]> {
    /// Returns a mutable slice to the underlying memory. This method is only
    /// available for SVSM-local mappings.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the referenced memory is not aliased
    /// (mutably or immutably) anywhere else.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: this type ensures that memory stays mapped and that the
        // accessed virtual addresses are properly aligned. The caller must
        // guarantee the rest of the safety requirements.
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr::<T>(), self.len()) }
    }
}
