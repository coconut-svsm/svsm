// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

use super::call::{syscall1, syscall3, SysCallError};
use super::def::{FileFlags, FileModes, SYS_OPEN, SYS_OPENDIR, SYS_READDIR};
use super::{DirEnt, Obj, ObjHandle};
use core::ffi::CStr;

#[derive(Debug)]
pub struct FsObjHandle(ObjHandle);

impl Obj for FsObjHandle {
    fn id(&self) -> u32 {
        u32::from(&self.0)
    }
}

pub fn opendir(path: &CStr) -> Result<FsObjHandle, SysCallError> {
    unsafe {
        syscall1(SYS_OPENDIR, path.as_ptr() as u64)
            .map(|ret| FsObjHandle(ObjHandle::new(ret as u32)))
    }
}

pub fn readdir(fs: &FsObjHandle, dirents: &mut [DirEnt]) -> Result<usize, SysCallError> {
    unsafe {
        syscall3(
            SYS_READDIR,
            fs.id().into(),
            dirents.as_mut_ptr() as u64,
            dirents.len() as u64,
        )
        .map(|ret| ret.try_into().unwrap())
    }
}

pub fn open(path: &CStr, mode: FileModes, flags: FileFlags) -> Result<FsObjHandle, SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe {
        syscall3(
            SYS_OPEN,
            path.as_ptr() as u64,
            mode.bits() as u64,
            flags.bits() as u64,
        )
        .map(|ret| FsObjHandle(ObjHandle::new(ret as u32)))
    }
}
