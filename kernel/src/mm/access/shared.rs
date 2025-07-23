// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use super::{MappingRead, MappingWrite};
use crate::cpu::mem::{unsafe_copy_bytes, write_bytes};
use crate::error::SvsmError;
use zerocopy::{FromBytes, IntoBytes};

/// An empty structure to indicate access to hypervisor-shared memory.
#[derive(Debug, Clone, Copy)]
pub struct Shared;

impl MappingRead for Shared {
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

impl MappingWrite for Shared {
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
