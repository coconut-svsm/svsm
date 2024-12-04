// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::obj::{obj_add, obj_get};
use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::fs::{
    create_root, find_dir, mkdir_root, open_root, rmdir_root, truncate, unlink_root, DirEntry,
    FsError, FsObj, UserBuffer,
};
use crate::mm::guestmem::UserPtr;
use crate::task::current_task;
use alloc::sync::Arc;
use core::cmp::min;
use core::ffi::c_char;
use core::str;
use syscall::SysCallError::*;
use syscall::*;

pub fn sys_open(path: usize, mode: usize, flags: usize) -> Result<u64, SysCallError> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path));
    let user_path = user_path_ptr.read_c_string()?;
    let file_mode = FileModes::from_bits(mode).ok_or(SysCallError::EINVAL)?;
    let file_flags = FileFlags::from_bits(flags).ok_or(SysCallError::EINVAL)?;
    let file_handle = {
        let open_res = open_root(
            current_task().rootdir(),
            &user_path,
            file_mode.contains(FileModes::READ),
            file_mode.contains(FileModes::WRITE),
        );
        if open_res.is_ok() || !file_flags.contains(FileFlags::CREATE) {
            open_res
        } else {
            create_root(current_task().rootdir(), user_path.as_str())
        }
    }?;

    if file_mode.contains(FileModes::TRUNC) {
        truncate(&file_handle, 0)?;
    }

    if file_mode.contains(FileModes::APPEND) {
        file_handle.seek_end(0);
    }

    let id = obj_add(Arc::new(FsObj::new_file(file_handle)))?;

    Ok(u32::from(id).into())
}

pub fn sys_read(obj_id: u32, user_addr: usize, bytes: usize) -> Result<u64, SysCallError> {
    let fs_obj = obj_get(obj_id.into())?;
    let fs_obj = fs_obj.as_fs().ok_or(ENOTSUPP)?;

    let mut buffer = UserBuffer::new(VirtAddr::from(user_addr), bytes);

    fs_obj
        .read_buffer(&mut buffer)
        .map(|b| b as u64)
        .map_err(SysCallError::from)
}

pub fn sys_write(obj_id: u32, user_addr: usize, bytes: usize) -> Result<u64, SysCallError> {
    let fs_obj = obj_get(obj_id.into())?;
    let fs_obj = fs_obj.as_fs().ok_or(ENOTSUPP)?;

    let buffer = UserBuffer::new(VirtAddr::from(user_addr), bytes);

    fs_obj
        .write_buffer(&buffer)
        .map(|b| b as u64)
        .map_err(SysCallError::from)
}

pub fn sys_seek(obj_id: u32, offset: usize, raw_mode: usize) -> Result<u64, SysCallError> {
    let fs_obj = obj_get(obj_id.into())?;
    let fs_obj = fs_obj.as_fs().ok_or(ENOTSUPP)?;
    let mode = SeekMode::try_from(raw_mode).map_err(|_| SvsmError::FileSystem(FsError::inval()))?;

    let result = match mode {
        SeekMode::Absolute => fs_obj.seek_abs(offset),
        SeekMode::Relative => fs_obj.seek_rel(offset as isize),
        SeekMode::End => fs_obj.seek_end(offset),
    };

    result.map(|p| p as u64).map_err(SysCallError::from)
}

pub fn sys_truncate(obj_id: u32, length: usize) -> Result<u64, SysCallError> {
    let fs_obj = obj_get(obj_id.into())?;
    let fs_obj = fs_obj.as_fs().ok_or(ENOTSUPP)?;

    fs_obj
        .truncate(length)
        .map(|l| l as u64)
        .map_err(SysCallError::from)
}

pub fn sys_unlink(path: usize) -> Result<u64, SysCallError> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path));
    let user_path = user_path_ptr.read_c_string()?;

    unlink_root(current_task().rootdir(), &user_path).map_err(SysCallError::from)?;

    Ok(0)
}

pub fn sys_opendir(path: usize) -> Result<u64, SysCallError> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path));
    let user_path = user_path_ptr.read_c_string()?;
    let dir = find_dir(current_task().rootdir(), &user_path)?;
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
        // DirEnt.file_name must be nul-terminated
        let bound = (0..min(name.len() + 1, new_entry.file_name.len()))
            .rposition(|i| name.is_char_boundary(i))
            .ok_or(EINVAL)?;
        new_entry.file_name[..bound].copy_from_slice(&name.as_bytes()[..bound]);
        if bound != name.len() {
            // Use unwrap() here since SVSM's filesystem should guarantee
            // that file names are valid UTF-8
            log::info!(
                "sys_readdir: truncation detected: {}",
                str::from_utf8(&new_entry.file_name[..bound]).unwrap()
            );
        }

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

pub fn sys_mkdir(path: usize) -> Result<u64, SysCallError> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path));
    let user_path = user_path_ptr.read_c_string()?;

    mkdir_root(current_task().rootdir(), &user_path).map_err(SysCallError::from)?;

    Ok(0)
}

pub fn sys_rmdir(path: usize) -> Result<u64, SysCallError> {
    let user_path_ptr = UserPtr::<c_char>::new(VirtAddr::from(path));
    let user_path = user_path_ptr.read_c_string()?;

    rmdir_root(current_task().rootdir(), &user_path).map_err(SysCallError::from)?;

    Ok(0)
}
