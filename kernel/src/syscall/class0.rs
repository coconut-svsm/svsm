// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::obj::{obj_close, obj_get};
use crate::address::VirtAddr;
use crate::cpu::percpu::current_task;
use crate::fs::find_dir;
use crate::mm::guestmem::UserPtr;
use crate::mm::vm::VMFileMappingFlags;
use crate::task::{current_task_terminated, exec_user, schedule};
use core::ffi::c_char;
use syscall::{MMFlags, SysCallError};

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
    let user_file_ptr = UserPtr::<c_char>::new(VirtAddr::from(file));
    let user_root_ptr = UserPtr::<c_char>::new(VirtAddr::from(root));

    let file_str = user_file_ptr.read_c_string()?;
    let root_str = user_root_ptr.read_c_string()?;
    let real_root = find_dir(current_task().rootdir(), &root_str)?;
    let tid = exec_user(&file_str, real_root)?;

    Ok(tid.into())
}

pub fn sys_mmap(
    obj_id: u32,
    addr: usize,
    offset: usize,
    size: usize,
    flags: usize,
) -> Result<u64, SysCallError> {
    let mm_flags = MMFlags::from_bits(flags).ok_or(SysCallError::EINVAL)?;
    let virt_addr = VirtAddr::from(addr);
    let vm_flags = VMFileMappingFlags::from(mm_flags);
    let opt = obj_get(obj_id.into()).ok();
    let mmap_addr = if let Some(obj) = opt {
        let fs_obj = obj.as_fs().ok_or(SysCallError::EINVAL)?;
        let fh = fs_obj.file_handle();
        current_task()
            .mmap_user(virt_addr, fh, offset, size, vm_flags)
            .map_err(SysCallError::from)?
    } else {
        current_task()
            .mmap_user(virt_addr, None, offset, size, vm_flags)
            .map_err(SysCallError::from)?
    };

    Ok(mmap_addr.into())
}

pub fn sys_close(obj_id: u32) -> Result<u64, SysCallError> {
    // According to syscall ABI/API spec, close always returns 0 even
    // if called with an invalid handle
    let _ = obj_close(obj_id.into());
    Ok(0)
}
