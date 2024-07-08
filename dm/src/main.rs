// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use syscall::exit;

fn dm_exit() -> ! {
    exit(0);
}

#[no_mangle]
pub extern "C" fn dm_start() -> ! {
    dm_exit();
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    dm_exit();
}
