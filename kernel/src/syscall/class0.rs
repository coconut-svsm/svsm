// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::obj::obj_close;
use crate::task::{current_task_terminated, schedule};
use syscall::SysCallError;

pub fn sys_exit(exit_code: u32) -> ! {
    log::info!("Terminating current task, exit_code {exit_code}");
    unsafe {
        current_task_terminated();
    }
    schedule();
    unreachable!("schedule() returned in sys_exit()");
}

pub fn sys_close(obj_id: u32) -> Result<u64, SysCallError> {
    // According to syscall ABI/API spec, close always returns 0 even
    // if called with an invalid handle
    let _ = obj_close(obj_id.into());
    Ok(0)
}
