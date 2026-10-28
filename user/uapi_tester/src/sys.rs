// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Advanced Micro Devices, Inc
//
// Author: Mahmoud Nagy Adam <madam@amd.com>

//! Safe wrappers of the raw system call functions, for the tests that issue
//! system calls directly.

use userlib::{SysCallError, syscall3};

/// Issues a system call with three arguments.
pub fn sys3(nr: u64, a: u64, b: u64, c: u64) -> Result<u64, SysCallError> {
    // SAFETY: the kernel validates the system call number and the arguments.
    // The pointers passed by the tests are either valid for the length given
    // or deliberately invalid, in which case the kernel fails the call with
    // EFAULT instead of accessing them. A caller that passes a pointer must
    // make sure that it stays valid for as long as the kernel may use it.
    unsafe { syscall3(nr, a, b, c) }
}
