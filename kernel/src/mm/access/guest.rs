// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use super::{MappingRead, MappingWrite, OwnedMapping};
use crate::address::PhysAddr;
use crate::mm::guestmem::do_movsb;
use crate::{error::SvsmError, mm::memory::valid_phys_region};
use zerocopy::{FromBytes, IntoBytes};

/// An empty structure to indicate access to guest-shared memory.
#[derive(Debug, Clone, Copy)]
pub struct Guest;

impl MappingRead for Guest {
    unsafe fn read<T: FromBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
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

impl MappingWrite for Guest {
    unsafe fn write<T: IntoBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        // TODO: optimize this
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

impl<T> OwnedMapping<Guest, T> {
    /// Maps the given physical address of guest memory. This method is safe
    /// because it checks that the mapped region belongs to the guest.
    ///
    /// # Errors
    ///
    /// Other than due to allocation failures or page table mainupulation
    /// errors, this function may fail if the provided physical address is not
    /// present in the guest's memory map.
    pub fn map_guest(paddr: PhysAddr) -> Result<Self, SvsmError> {
        if !valid_phys_region(&Self::phys_region(paddr, 1)?) {
            return Err(SvsmError::Mem);
        }
        Self::map::<false>(paddr)
    }

    /// Maps the given physical address of guest memory as a slice with a
    /// dynamic size. This method is safe because it checks that the mapped
    /// region belongs to the guest.
    ///
    /// # Errors
    ///
    /// Other than due to allocation failures or page table mainupulation
    /// errors, this function may fail if the provided physical address is not
    /// present in the guest's memory map.
    pub fn map_guest_slice(
        paddr: PhysAddr,
        len: usize,
    ) -> Result<OwnedMapping<Guest, [T]>, SvsmError> {
        if !valid_phys_region(&Self::phys_region(paddr, len)?) {
            return Err(SvsmError::Mem);
        }
        Self::map_slice::<false>(paddr, len)
    }
}
