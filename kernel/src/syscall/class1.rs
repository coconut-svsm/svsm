// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::obj::{obj_add, obj_get};
use crate::address::VirtAddr;
use crate::fs::{opendir, DirEntry, FileNameArray, FsObj};
use crate::mm::guestmem::UserPtr;
use alloc::sync::Arc;
use core::ffi::c_char;
use syscall::SysCallError::*;
use syscall::{DirEnt, FileType, SysCallError};

pub fn sys_opendir(path: usize) -> Result<u64, SysCallError> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path));
    let user_path = user_path_ptr.read_c_string()?;

    let dir = opendir(&user_path)?;
    let id = obj_add(Arc::new(FsObj::new_dir(&dir)))?;

    Ok(u32::from(id).into())
}

pub fn sys_readdir(obj_id: u32, dirents: usize, size: usize) -> Result<u64, SysCallError> {
    let fsobj = obj_get(obj_id.into())?;
    let fsobj = fsobj.as_fs().ok_or(ENOTSUPP)?;
    let user_dirents_ptr = UserPtr::<DirEnt>::new(VirtAddr::from(dirents));

    for i in 0..size {
        let Some((name, dirent)) = fsobj.readdir()? else {
            return Ok(i as u64);
        };

        let mut new_entry = DirEnt::default();
        let fname = FileNameArray::from(name);
        new_entry.file_name[..fname.len()].copy_from_slice(&fname);

        if let DirEntry::File(f) = dirent {
            new_entry.file_type = FileType::File;
            new_entry.file_size = f.size().try_into().unwrap();
        } else {
            new_entry.file_type = FileType::Directory;
            new_entry.file_size = 0;
        }

        let user_dirents_ptr = user_dirents_ptr.offset(i.try_into().unwrap());
        user_dirents_ptr.write(new_entry)?
    }
    Ok(size as u64)
}
