// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
extern crate alloc;

use super::obj::obj_close;
use crate::address::VirtAddr;
use crate::cpu::percpu::current_task;
use crate::error::SvsmError;
use crate::fs::{find_dir, FsError};
use crate::mm::guestmem::UserPtr;
use crate::task::{current_task_terminated, exec_user, schedule, TaskError};
use alloc::vec::Vec;
use core::ffi::c_char;
use syscall::{EINVAL, ENOTFOUND};

pub fn sys_exit(exit_code: u32) -> ! {
    log::info!("Terminating current task, exit_code {exit_code}");
    unsafe {
        current_task_terminated();
    }
    schedule();
    panic!("schedule() returned in sys_exit()");
}

pub fn sys_exec(file: usize, root: usize, _flags: usize) -> Result<u64, i32> {
    let user_file_ptr = UserPtr::<c_char>::new(VirtAddr::from(file)).map_err(|_| EINVAL)?;
    let user_root_ptr = UserPtr::<c_char>::new(VirtAddr::from(root)).map_err(|_| EINVAL)?;
    let mut file_buffer = Vec::new();
    let mut root_buffer = Vec::new();

    unsafe {
        let file_str = user_file_ptr
            .read_c_string(&mut file_buffer)
            .map_err(|_| EINVAL)?;
        let root_str = user_root_ptr
            .read_c_string(&mut root_buffer)
            .map_err(|_| EINVAL)?;
        let real_root = find_dir(current_task().get_rootdir(), root_str).map_err(|e| match e {
            SvsmError::FileSystem(FsError::FileNotFound) => ENOTFOUND,
            _ => EINVAL,
        })?;
        match exec_user(file_str, real_root) {
            Ok(tid) => Ok(tid.into()),
            Err(SvsmError::Task(TaskError::Terminated)) => Err(ENOTFOUND),
            _ => Err(EINVAL),
        }
    }
}

pub fn sys_close(obj_id: u32) -> Result<u64, i32> {
    // According to syscall ABI/API spec, close always returns 0 even
    // if called with an invalid handle
    let _ = obj_close(obj_id.into());
    Ok(0)
}
