// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::task::{current_task_terminated, schedule};

pub fn sys_hello() -> usize {
    log::info!("Hello, world! System call invoked from user-space.");
    0
}

pub fn sys_exit() -> ! {
    log::info!("Terminating current task");
    unsafe {
        current_task_terminated();
    }
    schedule();
    panic!("schedule() returned in sys_exit()");
}
