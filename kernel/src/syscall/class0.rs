// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::task::{current_task_terminated, schedule};

pub fn sys_exit(exit_code: u32) -> ! {
    log::info!("Terminating current task, exit_code {exit_code}");
    unsafe {
        current_task_terminated();
    }
    schedule();
    panic!("schedule() returned in sys_exit()");
}
