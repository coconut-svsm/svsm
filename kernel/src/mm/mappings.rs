// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::mm::vm::{Mapping, VMFileMapping, VMFileMappingFlags, VMalloc};
use crate::task::current_task;

extern crate alloc;
use alloc::sync::Arc;

pub fn create_file_mapping(
    file: &FileHandle,
    offset: usize,
    size: usize,
    flags: VMFileMappingFlags,
) -> Result<Mapping, SvsmError> {
    let file_mapping = VMFileMapping::new(file, offset, size, flags)?;
    Ok(Arc::new(file_mapping))
}

pub fn create_anon_mapping(size: usize, flags: VMFileMappingFlags) -> Result<Mapping, SvsmError> {
    let alloc = VMalloc::new(size, flags)?;
    Ok(Arc::new(alloc))
}

pub fn mmap_user(
    addr: VirtAddr,
    file: Option<&FileHandle>,
    offset: usize,
    size: usize,
    flags: VMFileMappingFlags,
) -> Result<VirtAddr, SvsmError> {
    current_task().mmap_user(addr, file, offset, size, flags)
}

pub fn mmap_kernel(
    addr: VirtAddr,
    file: Option<&FileHandle>,
    offset: usize,
    size: usize,
    flags: VMFileMappingFlags,
) -> Result<VirtAddr, SvsmError> {
    current_task().mmap_kernel(addr, file, offset, size, flags)
}

pub fn munmap_user(addr: VirtAddr) -> Result<(), SvsmError> {
    current_task().munmap_user(addr)
}

pub fn munmap_kernel(addr: VirtAddr) -> Result<(), SvsmError> {
    current_task().munmap_kernel(addr)
}
