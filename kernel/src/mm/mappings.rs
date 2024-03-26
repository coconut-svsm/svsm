// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::mm::vm::{Mapping, VMFileMapping, VMFileMappingFlags, VMalloc};

extern crate alloc;
use alloc::sync::Arc;

pub fn create_file_mapping(
    file: &FileHandle,
    offset: usize,
    size: usize,
    flags: VMFileMappingFlags,
) -> Result<Arc<Mapping>, SvsmError> {
    let file_mapping = VMFileMapping::new(file, offset, size, flags)?;
    Ok(Arc::new(Mapping::new(file_mapping)))
}

pub fn create_anon_mapping(size: usize) -> Result<Arc<Mapping>, SvsmError> {
    let alloc = VMalloc::new(size)?;
    Ok(Arc::new(Mapping::new(alloc)))
}
