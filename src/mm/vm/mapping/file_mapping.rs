// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::vec::Vec;

use super::{RawAllocMapping, VirtualMapping};
use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::mm::PageRef;
use crate::mm::{pagetable::PageTable, PAGE_SIZE};
use crate::types::PAGE_SHIFT;
use crate::utils::align_up;

#[derive(Debug)]
struct VMWriteFileMapping(RawAllocMapping);

impl VirtualMapping for VMWriteFileMapping {
    fn mapping_size(&self) -> usize {
        self.0.mapping_size()
    }

    fn map(&self, offset: usize) -> Option<crate::address::PhysAddr> {
        self.0.map(offset)
    }

    fn pt_flags(&self, _offset: usize) -> crate::mm::pagetable::PTEntryFlags {
        PageTable::task_data_flags()
    }
}

#[derive(Debug, PartialEq)]
pub enum VMFileMappingPermission {
    /// Read-only access to the file
    Read,
    // Read/Write access to a copy of the files pages
    Write,
    // Read-only access that allows execution
    Execute,
}

/// Map view of a ramfs file into virtual memory
#[derive(Debug)]
pub struct VMFileMapping {
    /// The file that this mapping relates to
    file: FileHandle,

    /// The size of the mapping in bytes
    size: usize,

    /// The permission to apply to the virtual mapping
    permission: VMFileMappingPermission,

    /// A vec containing references to mapped pages within the file
    pages: Vec<Option<PageRef>>,
}

impl VMFileMapping {
    /// Create a new ['VMFileMapping'] for a file. The file provides the backing
    /// pages for the file contents.
    ///
    /// # Arguments
    ///
    /// * 'file' - The file to create the mapping for. This instance keeps a
    ///            reference to the file until it is dropped.
    ///
    /// * 'offset' - The offset from the start of the file to map. This must be
    ///   align to PAGE_SIZE.
    ///
    /// * 'size' - The number of bytes to map starting from the offset. This
    ///   must be a multiple of PAGE_SIZE.
    ///
    /// # Returns
    ///
    /// Initialized mapping on success, Err(SvsmError::Mem) on error
    pub fn new(
        file: FileHandle,
        offset: usize,
        size: usize,
        permission: VMFileMappingPermission,
    ) -> Result<Self, SvsmError> {
        let page_size = align_up(size, PAGE_SIZE);
        let file_size = align_up(file.size(), PAGE_SIZE);
        if (offset & (PAGE_SIZE - 1)) != 0 {
            return Err(SvsmError::Mem);
        }
        if (page_size + offset) > file_size {
            return Err(SvsmError::Mem);
        }

        // Take references to the file pages
        let count = page_size >> PAGE_SHIFT;
        let mut pages = Vec::<Option<PageRef>>::new();
        for page_index in 0..count {
            pages.push(file.mapping(offset + page_index * PAGE_SIZE));
        }

        Ok(Self {
            file,
            size: page_size,
            permission,
            pages,
        })
    }
}

impl VirtualMapping for VMFileMapping {
    fn mapping_size(&self) -> usize {
        self.size
    }

    fn map(&self, offset: usize) -> Option<crate::address::PhysAddr> {
        let page_index = offset / PAGE_SIZE;
        if page_index >= self.pages.len() {
            return None;
        }
        self.pages[page_index].as_ref().map(|p| p.phys_addr())
    }

    fn pt_flags(&self, _offset: usize) -> crate::mm::pagetable::PTEntryFlags {
        match self.permission {
            VMFileMappingPermission::Read => PageTable::task_data_ro_flags(),
            VMFileMappingPermission::Write => PageTable::task_data_flags(),
            VMFileMappingPermission::Execute => PageTable::task_exec_flags(),
        }
    }
}
