// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

extern crate alloc;

use super::{BorrowedMapping, Mapping, MappingRead, MappingWrite, ReadableMapping};
use crate::address::{Address, VirtAddr};
use crate::cpu::x86::smap::{clac, stac};
use crate::error::SvsmError;
use crate::mm::guestmem::do_movsb;
use crate::mm::{USER_MEM_END, USER_MEM_START};
use crate::utils::MemoryRegion;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_char;
use core::marker::PhantomData;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug)]
struct UserAccessGuard;

impl UserAccessGuard {
    pub fn new() -> Self {
        stac();
        Self
    }
}

impl Drop for UserAccessGuard {
    fn drop(&mut self) {
        clac();
    }
}

/// An empty structure indicating access to SVSM userspace.
#[derive(Clone, Copy, Debug)]
pub struct User;

impl MappingRead for User {
    unsafe fn read<T: FromBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        let _guard = UserAccessGuard::new();
        // TODO: optimize this to a single call
        for i in 0..count {
            // SAFETY: safety requirements must be upheld by the caller
            unsafe {
                do_movsb(src.add(i), dst.add(i))?;
            }
        }
        Ok(())
    }
}

impl MappingWrite for User {
    unsafe fn write<T: zerocopy::IntoBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        let _guard = UserAccessGuard::new();
        // TODO: optimize this to a single call
        for i in 0..count {
            // SAFETY: safety requirements must be upheld by the caller
            unsafe {
                do_movsb(src.add(i), dst.add(i))?;
            }
        }
        Ok(())
    }

    unsafe fn write_bytes<T: IntoBytes>(_: *mut T, _: usize, _: u8) -> Result<(), SvsmError> {
        unimplemented!()
    }
}

impl<'a, T> BorrowedMapping<'a, User, T> {
    fn checked_region(start: VirtAddr, len: usize) -> Result<MemoryRegion<VirtAddr>, SvsmError> {
        let end = len
            .checked_mul(size_of::<T>())
            .and_then(|ln| start.checked_add(ln))
            .ok_or(SvsmError::ArithOverflow)?;
        let region = MemoryRegion::from_addresses(start, end);
        let is_user = (USER_MEM_START..USER_MEM_END).contains(&region.start())
            && (USER_MEM_START..USER_MEM_END).contains(&region.end());
        if is_user {
            Ok(region)
        } else {
            Err(SvsmError::InvalidAddress)
        }
    }

    /// This function is safe because it checks that the resulting virtual
    /// memory region (starting at `addr`) is within the userspace region
    /// of the virtual address space.
    pub fn user_from_address(addr: VirtAddr) -> Result<Self, SvsmError> {
        let region = Self::checked_region(addr, 1)?;
        Ok(Self {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }

    /// This function is safe because it checks that the resulting virtual
    /// memory region (starting at `addr`) is within the userspace region
    /// of the virtual address space.
    pub fn user_slice_from_address(
        addr: VirtAddr,
        len: usize,
    ) -> Result<BorrowedMapping<'a, User, [T]>, SvsmError> {
        let region = Self::checked_region(addr, len)?;
        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }
}

impl BorrowedMapping<'_, User, c_char> {
    /// Reads a null-terminateed C string from the starting address of the
    /// current mapping and performs UTF8 conversion to place the result in an
    /// allocated [`String`].
    pub fn read_c_string(&self) -> Result<String, SvsmError> {
        // Take a mapping that spans all userspace and begin reading.
        // self.region is valid by construction, and we make sure not to
        // exceed the end of user memory.
        let user = Self {
            region: MemoryRegion::new(self.region.start(), USER_MEM_END - self.region.start()),
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        };

        let mut buffer = Vec::new();

        for offset in 0..syscall::PATH_MAX {
            let ch = user
                .borrow_at(offset * size_of::<c_char>())
                .unwrap()
                .read()?;
            match ch {
                0 => return String::from_utf8(buffer).map_err(|_| SvsmError::InvalidUtf8),
                c => buffer.push(c as u8),
            }
        }
        Err(SvsmError::InvalidBytes)
    }
}
