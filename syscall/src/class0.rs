// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
// Copyright (c) 2026 Advanced Micro Devices, Inc.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>
//         Joerg Roedel <joerg.roedel@amd.com>

use super::call::{SysCallError, syscall1, syscall2, syscall3, syscall5};
use super::{MMFlags, ObjHandle, SYS_EXEC, SYS_EXIT, SYS_MMAP, SYS_MRESIZE, SYS_MUNMAP};
use core::ffi::CStr;

pub fn exit(code: u32) -> ! {
    // SAFETY: SYS_EXIT is supported syscall number by the svsm kernel.
    unsafe {
        let _ = syscall1(SYS_EXIT, u64::from(code));
    }
    unreachable!("Should never return from SYS_EXIT syscall");
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tid(u32);

/// Creates a memory mapping in the calling task
///
/// # Arguments
///
/// * `handle` - An object handle of none for anonymous mappings.
/// * `addr` - Virtual address hint.
/// * `offset` - File offset.
/// * `length` - Length of mapping.
/// * `flags` - Mapping flags.
///
/// # Returns
///
/// Result with start address of created mapping on success and SysCallError on
/// failure.
///
/// # Safety
///
/// Caller must ensure that changing the task memory layout does not impact
/// Rust memory safety.
pub unsafe fn mmap(
    handle: Option<&ObjHandle>,
    addr: usize,
    offset: u64,
    length: u64,
    flags: MMFlags,
) -> Result<usize, SysCallError> {
    let obj: u64 = if let Some(fd) = handle {
        fd.id().into()
    } else {
        0u64
    };
    // SAFETY: Safe as long as the safety requirements of the function are met.
    unsafe {
        syscall5(
            SYS_MMAP,
            obj,
            addr as u64,
            offset,
            length,
            flags.bits() as u64,
        )
        .map(|ret| ret.try_into().unwrap())
    }
}

/// Removes a memory mapping from the calling task
///
/// # Arguments
///
/// * `addr` - Virtual start address of mapping.
/// * `length` - Length of mapping, must match the length when the mapping was
///   created or last changed.
///
/// # Returns
///
/// Returns a Result with SysCallError on failure.
///
/// # Safety
///
/// Caller must ensure that changing the task memory layout does not impact
/// Rust memory safety.
pub unsafe fn munmap(addr: usize, length: u64) -> Result<(), SysCallError> {
    // SAFETY: Safe as long as the safety requirements of the function are met.
    unsafe { syscall2(SYS_MUNMAP, addr as u64, length).map(|_| ()) }
}

/// Resizes a memory mapping in the calling task.
///
/// # Arguments
///
/// * `addr` - Virtual start address of mapping.
/// * `length` - New length of mapping.
///
/// # Returns
///
/// Returns a Result with SysCallError on failure.
///
/// # Safety
///
/// Caller must ensure that changing the task memory layout does not impact
/// Rust memory safety.
pub unsafe fn mresize(addr: usize, length: u64) -> Result<(), SysCallError> {
    // SAFETY: Safe as long as the safety requirements of the function are met.
    unsafe { syscall2(SYS_MRESIZE, addr as u64, length).map(|_| ()) }
}

pub fn exec(file: &CStr, root: &CStr, flags: u32) -> Result<Tid, SysCallError> {
    // SAFETY:
    // 1. SYS_EXEC is a supported syscall number by the svsm kernel.
    // 2. Parameters `file.as_ptr()` and `root.as_ptr()` are passed as raw pointers.
    // but the function `sys_exec` which this function delegates to, performs the
    // necessary checks.
    // 3. Currently `flags` parameter is unused.
    unsafe {
        syscall3(
            SYS_EXEC,
            file.as_ptr() as u64,
            root.as_ptr() as u64,
            u64::from(flags),
        )
        .map(|ret| Tid(ret as u32))
    }
}
