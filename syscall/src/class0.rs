// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::call::{syscall1, syscall3, SysCallError};
use super::{SYS_EXEC, SYS_EXIT};
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

pub fn exec(file: &CStr, root: &CStr, flags: u32) -> Result<Tid, SysCallError> {
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
