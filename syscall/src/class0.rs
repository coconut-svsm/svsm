// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::call::syscall1;
use super::SYS_EXIT;

pub fn exit(code: u32) -> ! {
    // SAFETY: SYS_EXIT is supported syscall number by the svsm kernel.
    unsafe {
        let _ = syscall1(SYS_EXIT, u64::from(code));
    }
    unreachable!("Should never return from SYS_EXIT syscall");
}
