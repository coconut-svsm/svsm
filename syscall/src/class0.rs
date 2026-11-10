// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::SysNo;
use super::call::{SysCallError, syscall1, syscall3};
use core::ffi::CStr;

/// Terminate the current task with the given exit code. Like on Linux, only
/// the low 8 bits of the code are used.
pub fn exit(code: u32) -> ! {
    // SAFETY: ExitGroup is supported syscall number by the svsm kernel.
    unsafe {
        let _ = syscall1(SysNo::ExitGroup as u64, u64::from(code));
    }
    unreachable!("Should never return from ExitGroup syscall");
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tid(u32);

pub fn exec(file: &CStr, root: &CStr, flags: u32) -> Result<Tid, SysCallError> {
    // SAFETY:
    // 1. SvsmExec is a supported syscall number by the svsm kernel.
    // 2. Parameters `file.as_ptr()` and `root.as_ptr()` are passed as raw pointers.
    // but the function `sys_exec` which this function delegates to, performs the
    // necessary checks.
    // 3. Currently `flags` parameter is unused.
    unsafe {
        syscall3(
            SysNo::SvsmExec as u64,
            file.as_ptr() as u64,
            root.as_ptr() as u64,
            u64::from(flags),
        )
        .map(|ret| Tid(ret as u32))
    }
}
