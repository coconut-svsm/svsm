// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

use super::call::{syscall1, syscall3, SysCallError};
use super::def::{
    FileFlags, FileModes, SeekMode, SYS_OPEN, SYS_OPENDIR, SYS_READ, SYS_READDIR, SYS_SEEK,
    SYS_WRITE,
};
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

pub fn read(fd: &FsObjHandle, buffer: &mut [u8]) -> Result<usize, SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process. All memory changes happen from kernel context.
    unsafe {
        syscall3(
            SYS_READ,
            fd.id().into(),
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
        )
        .map(|ret| ret.try_into().unwrap())
    }
}

pub fn write(fd: &FsObjHandle, buffer: &[u8]) -> Result<usize, SysCallError> {
    // SAFETY: Invokes a system call and does not change memory of the process.
    // Kernel will only read from process memory.
    unsafe {
        syscall3(
            SYS_WRITE,
            fd.id().into(),
            buffer.as_ptr() as u64,
            buffer.len() as u64,
        )
        .map(|ret| ret.try_into().unwrap())
    }
}

pub fn seek(fd: &FsObjHandle, offset: i64, mode: SeekMode) -> Result<u64, SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe { syscall3(SYS_SEEK, fd.id().into(), offset as u64, mode as u64) }
}
