// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::call::{syscall1, SysCallError};
use super::SYS_CAPABILITIES;

pub fn capabilities(index: u32) -> Result<u64, SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe { syscall1(SYS_CAPABILITIES, index.into()) }
}
