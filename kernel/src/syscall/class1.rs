// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::obj::{obj_add, obj_get};
use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::fs::{opendir, DirEntry, FileNameArray, FsError, FsObj};
use crate::mm::guestmem::UserPtr;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_char;
use syscall::{DirEnt, EINVAL, ENOTFOUND, ENOTSUPP, F_TYPE_DIR, F_TYPE_FILE};

pub fn sys_opendir(path: usize) -> Result<u64, i32> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path)).map_err(|_| EINVAL)?;
    let mut path_buffer = Vec::new();
    unsafe {
        let path = user_path_ptr
            .read_c_string(&mut path_buffer)
            .map_err(|_| EINVAL)?;
        let dir = opendir(path).map_err(|e| match e {
            SvsmError::FileSystem(FsError::FileNotFound) => ENOTFOUND,
            _ => EINVAL,
        })?;
        obj_add(Arc::new(FsObj::new_dir(&dir))).map_or(Err(EINVAL), |id| Ok(u32::from(id).into()))
    }
}

pub fn sys_readdir(obj_id: u32, dirents: usize, size: usize) -> Result<u64, i32> {
    let fsobj = obj_get(obj_id.into()).map_err(|_| ENOTFOUND)?;
    let fsobj = fsobj.as_fs().ok_or(ENOTSUPP)?;
    let user_dirents_ptr = UserPtr::<DirEnt>::new(VirtAddr::from(dirents)).map_err(|_| EINVAL)?;

    for i in 0..size {
        match fsobj.readdir() {
            Ok(Some((name, dirent))) => {
                let mut new_entry = DirEnt::default();
                let fname = FileNameArray::from(name);
                let last_n = new_entry.file_name.len() - 1;

                for (n, c) in new_entry.file_name.iter_mut().enumerate() {
                    if n == last_n || n == fname.len() {
                        *c = b'\0';
                        break;
                    } else {
                        *c = fname[n];
                        if *c == b'\0' {
                            break;
                        }
                    }
                }
                if let DirEntry::File(ref f) = dirent {
                    new_entry.file_type = F_TYPE_FILE;
                    new_entry.file_size = f.size().try_into().unwrap();
                } else {
                    new_entry.file_type = F_TYPE_DIR;
                    new_entry.file_size = 0;
                }

                let user_dirents_ptr = user_dirents_ptr.offset(i.try_into().unwrap());
                unsafe { user_dirents_ptr.write(new_entry).map_err(|_| EINVAL)? }
            }
            Ok(None) => return Ok(i as u64),
            _ => return Err(EINVAL),
        }
    }
    Ok(size as u64)
}
