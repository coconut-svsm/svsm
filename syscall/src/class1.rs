// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

use super::call::{syscall1, syscall2, syscall3, SysCallError};
use super::def::{
    FileFlags, FileModes, SeekMode, SYS_MKDIR, SYS_OPEN, SYS_OPENDIR, SYS_READ, SYS_READDIR,
    SYS_RMDIR, SYS_SEEK, SYS_TRUNCATE, SYS_UNLINK, SYS_WRITE,
};
use super::{DirEnt, Obj, ObjHandle};
use core::ffi::CStr;

#[derive(Debug)]
pub struct FsObjHandle(ObjHandle);

impl FsObjHandle {
    pub(crate) const fn new(obj: ObjHandle) -> Self {
        Self(obj)
    }
}

impl Obj for FsObjHandle {
    fn id(&self) -> u32 {
        u32::from(&self.0)
    }
}

pub fn opendir(path: &CStr) -> Result<FsObjHandle, SysCallError> {
    // SAFETY: SYS_OPENDIR is supported syscall number by the svsm kernel.
    unsafe {
        syscall1(SYS_OPENDIR, path.as_ptr() as u64)
            .map(|ret| FsObjHandle(ObjHandle::new(ret as u32)))
    }
}

pub fn readdir(fs: &FsObjHandle, dirents: &mut [DirEnt]) -> Result<usize, SysCallError> {
    // SAFETY: SYS_READDIR is supported syscall number by the svsm kernel.
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

pub fn truncate(fd: &FsObjHandle, length: u64) -> Result<u64, SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe { syscall2(SYS_TRUNCATE, fd.id().into(), length) }
}

pub fn unlink(path: &CStr) -> Result<(), SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe { syscall1(SYS_UNLINK, path.as_ptr() as u64).map(|_| ()) }
}

pub fn mkdir(path: &CStr) -> Result<(), SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe { syscall1(SYS_MKDIR, path.as_ptr() as u64).map(|_| ()) }
}

pub fn rmdir(path: &CStr) -> Result<(), SysCallError> {
    // SAFETY: Invokes a system call and does not directly change any memory of
    // the process.
    unsafe { syscall1(SYS_RMDIR, path.as_ptr() as u64).map(|_| ()) }
}
