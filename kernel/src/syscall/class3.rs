// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use crate::platform::capabilities::Cap;
use crate::platform::CAPS;
use syscall::SysCallError;

pub fn sys_capabilities(index: u32) -> Result<u64, SysCallError> {
    let cap = match index {
        0 => Cap::NrCaps,
        i if i <= Cap::NrCaps as u32 => (i - 1).try_into().unwrap(),
        _ => return Err(SysCallError::ENOTFOUND),
    };
    Ok(CAPS.get(cap))
}
