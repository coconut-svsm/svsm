// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::obj::obj_close;
use crate::cpu::percpu::current_task;
use crate::fs::find_dir;
use crate::mm::access::BorrowedMapping;
use crate::task::{current_task_terminated, exec_user, schedule};
use syscall::SysCallError;

pub fn sys_exit(exit_code: u32) -> ! {
    log::info!(
        "Terminating task {}, exit_code {exit_code}",
        current_task().get_task_name()
    );
    current_task_terminated();
    schedule();
    unreachable!("schedule() returned in sys_exit()");
}

pub fn sys_exec(file: usize, root: usize, _flags: usize) -> Result<u64, SysCallError> {
    let user_file_ptr = BorrowedMapping::user_from_address(file.into())?;
    let user_root_ptr = BorrowedMapping::user_from_address(root.into())?;

    let file_str = user_file_ptr.read_c_string()?;
    let root_str = user_root_ptr.read_c_string()?;
    let real_root = find_dir(current_task().rootdir(), &root_str)?;
    let tid = exec_user(&file_str, real_root)?;

    Ok(tid.into())
}

pub fn sys_close(obj_id: u32) -> Result<u64, SysCallError> {
    // According to syscall ABI/API spec, close always returns 0 even
    // if called with an invalid handle
    let _ = obj_close(obj_id.into());
    Ok(0)
}
