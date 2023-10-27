// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::slice::from_raw_parts_mut;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{Mapping, RawAllocMapping, VMPageFaultResolution, VMPhysMem, VirtualMapping};
use crate::address::Address;
use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::mm::vm::VMR;
use crate::mm::PageRef;
use crate::mm::{pagetable::PageTable, PAGE_SIZE};
use crate::types::PAGE_SHIFT;
use crate::utils::align_up;

#[derive(Debug)]
struct VMWriteFileMapping(RawAllocMapping);

impl VMWriteFileMapping {
    pub fn get_alloc(&self) -> &RawAllocMapping {
        &self.0
    }

    pub fn get_alloc_mut(&mut self) -> &mut RawAllocMapping {
        &mut self.0
    }
}

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

    /// A copy of the file pages for mappings with Write permission
    write_copy: Option<VMWriteFileMapping>,
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
        // For ranges with write access we need to take a copy of the ram pages
        // to allow them to be written to without modifying the contents of the
        // file itself and also to prevent pointer aliasing with any other
        // FileHandles that may be open on the same file.
        let write_copy = if permission == VMFileMappingPermission::Write {
            Some(VMWriteFileMapping(RawAllocMapping::new(size)))
        } else {
            None
        };

        Ok(Self {
            file,
            size: page_size,
            permission,
            pages,
            write_copy,
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
        if let Some(write_copy) = &self.write_copy {
            let write_addr = write_copy.map(offset);
            if write_addr.is_some() {
                return write_addr;
            }
        }
        self.pages[page_index].as_ref().map(|p| p.phys_addr())
    }

    fn pt_flags(&self, offset: usize) -> crate::mm::pagetable::PTEntryFlags {
        match self.permission {
            VMFileMappingPermission::Read => PageTable::task_data_ro_flags(),
            VMFileMappingPermission::Write => {
                if let Some(write_copy) = &self.write_copy {
                    if write_copy.get_alloc().present(offset) {
                        PageTable::task_data_flags()
                    } else {
                        PageTable::task_data_ro_flags()
                    }
                } else {
                    PageTable::task_data_ro_flags()
                }
            }
            VMFileMappingPermission::Execute => PageTable::task_exec_flags(),
        }
    }

    fn handle_page_fault(
        &mut self,
        vmr: &VMR,
        offset: usize,
        write: bool,
    ) -> Result<VMPageFaultResolution, SvsmError> {
        let page_size = self.page_size();
        if write {
            if let Some(write_copy) = self.write_copy.as_mut() {
                // This is a writeable region with copy-on-write access. The
                // page fault will have occurred because the page has not yet
                // been allocated. Allocate a page and copy the readonly source
                // page into the new writeable page.
                let offset_aligned = offset & !(page_size - 1);
                if write_copy
                    .get_alloc_mut()
                    .alloc_page(offset_aligned)
                    .is_ok()
                {
                    let paddr_new_page = write_copy.map(offset_aligned).ok_or(SvsmError::Mem)?;
                    let temp_map = VMPhysMem::new(paddr_new_page, page_size, true);
                    let vaddr_new_page = vmr.insert(Arc::new(Mapping::new(temp_map)))?;
                    let slice =
                        unsafe { from_raw_parts_mut(vaddr_new_page.bits() as *mut u8, page_size) };
                    self.file.seek(offset_aligned);
                    self.file.read(slice)?;
                    vmr.remove(vaddr_new_page)?;
                    return Ok(VMPageFaultResolution {
                        paddr: paddr_new_page,
                        flags: PageTable::task_data_flags(),
                    });
                }
            }
        }
        Err(SvsmError::Mem)
    }
}
