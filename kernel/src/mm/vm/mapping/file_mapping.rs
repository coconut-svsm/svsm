// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::vec::Vec;

use bitflags::bitflags;

use super::{VMPageFaultResolution, VirtualMapping};
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fs::{FileHandle, FsError};
use crate::mm::vm::VMR;
use crate::mm::PageRef;
use crate::mm::{pagetable::PTEntryFlags, PAGE_SIZE};
use crate::types::PAGE_SHIFT;
use crate::utils::align_up;

bitflags! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub struct VMFileMappingFlags : u32 {
        /// Read-only access to the file
        const Read = 1 << 0;
        // Read/Write access to a copy of the files pages
        const Write = 1 << 1;
        // Read-only access that allows execution
        const Execute = 1 << 2;
        // Map private copies of file pages
        const Private = 1 << 3;
        // Map at a fixed address
        const Fixed = 1 << 4;
    }
}

/// Map view of a ramfs file into virtual memory
#[derive(Debug)]
pub struct VMFileMapping {
    /// The size of the mapping in bytes
    size: usize,

    /// The flags to apply to the virtual mapping
    flags: VMFileMappingFlags,

    /// A vec containing references to mapped pages within the file
    pages: Vec<PageRef>,
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
        file: &FileHandle,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<Self, SvsmError> {
        let page_size = align_up(size, PAGE_SIZE);
        let file_size = align_up(file.size(), PAGE_SIZE);

        // Check whether offset is page-aligned
        if (offset & (PAGE_SIZE - 1)) != 0 {
            return Err(SvsmError::Mem);
        }

        // Attempt to map beyon EOF?
        if (page_size + offset) > file_size {
            return Err(SvsmError::Mem);
        }

        // Permission checks
        if (flags.contains(VMFileMappingFlags::Write)
            && !flags.contains(VMFileMappingFlags::Private)
            && !file.writable())
            || (flags.contains(VMFileMappingFlags::Read) && !file.readable())
        {
            return Err(SvsmError::FileSystem(FsError::bad_handle()));
        }

        // Take references to the file pages
        let count = page_size >> PAGE_SHIFT;
        let mut pages = Vec::<PageRef>::new();
        for page_index in 0..count {
            let page_ref = file
                .mapping(offset + page_index * PAGE_SIZE)
                .ok_or(SvsmError::Mem)?;
            if flags.contains(VMFileMappingFlags::Private) {
                pages.push(page_ref.try_copy_page()?);
            } else {
                pages.push(page_ref);
            }
        }
        Ok(Self {
            size: page_size,
            flags,
            pages,
        })
    }
}

#[cfg(not(test))]
#[cfg(test)]
fn copy_page(
    _vmr: &VMR,
    file: &FileHandle,
    offset: usize,
    paddr_dst: PhysAddr,
    page_size: PageSize,
) -> Result<(), SvsmError> {
    let page_size = usize::from(page_size);
    // In the test environment the physical address is actually the virtual
    // address. We can take advantage of this to copy the file contents into the
    // mock physical address without worrying about VMRs and page tables.
    let slice = unsafe { from_raw_parts_mut(paddr_dst.bits() as *mut u8, page_size) };
    file.seek(offset);
    file.read(slice)?;
    Ok(())
}

impl VirtualMapping for VMFileMapping {
    fn mapping_size(&self) -> usize {
        self.size
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        let page_index = offset / PAGE_SIZE;
        if page_index >= self.pages.len() {
            return None;
        }
        Some(self.pages[page_index].phys_addr())
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        let mut flags = PTEntryFlags::empty();

        if self.flags.contains(VMFileMappingFlags::Write) {
            flags |= PTEntryFlags::WRITABLE;
        }

        if !self.flags.contains(VMFileMappingFlags::Execute) {
            flags |= PTEntryFlags::NX;
        }

        flags
    }

    fn handle_page_fault(
        &mut self,
        _vmr: &VMR,
        _offset: usize,
        _write: bool,
    ) -> Result<VMPageFaultResolution, SvsmError> {
        Err(SvsmError::Mem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fs::{create, open_rw, unlink, TestFileSystemGuard},
        mm::alloc::{TestRootMem, DEFAULT_TEST_MEMORY_SIZE},
        types::PAGE_SIZE,
    };

    fn create_512b_test_file() -> (FileHandle, &'static str) {
        let fh = create("test1").unwrap();
        let buf = [0xffu8; 512];
        fh.write(&buf).expect("File write failed");
        (fh, "test1")
    }

    fn create_16k_test_file() -> (FileHandle, &'static str) {
        let fh = create("test1").unwrap();
        let mut buf = [0xffu8; PAGE_SIZE * 4];
        buf[PAGE_SIZE] = 1;
        buf[PAGE_SIZE * 2] = 2;
        buf[PAGE_SIZE * 3] = 3;
        fh.write(&buf).expect("File write failed");
        (fh, "test1")
    }

    fn create_5000b_test_file() -> (FileHandle, &'static str) {
        let fh = create("test1").unwrap();
        let buf = [0xffu8; 5000];
        fh.write(&buf).expect("File write failed");
        (fh, "test1")
    }

    #[test]
    fn test_create_mapping() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_512b_test_file();
        let vm = VMFileMapping::new(&fh, 0, 512, VMFileMappingFlags::Read)
            .expect("Failed to create new VMFileMapping");
        assert_eq!(vm.mapping_size(), PAGE_SIZE);
        assert!(vm.flags.contains(VMFileMappingFlags::Read));
        assert_eq!(vm.pages.len(), 1);
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_unaligned_offset() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        // Not page aligned
        let offset = PAGE_SIZE + 0x60;

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, offset, fh2.size() - offset, VMFileMappingFlags::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_size_too_large() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, 0, fh2.size() + 1, VMFileMappingFlags::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_offset_overflow() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, PAGE_SIZE, fh2.size(), VMFileMappingFlags::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    fn test_map_first_page(flags: VMFileMappingFlags) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_512b_test_file();
        let vm =
            VMFileMapping::new(&fh, 0, 512, flags).expect("Failed to create new VMFileMapping");

        let res = vm
            .map(0)
            .expect("Mapping of first VMFileMapping page failed");

        let fh2 = open_rw(name).unwrap();
        assert_eq!(
            fh2.mapping(0)
                .expect("Failed to get file page mapping")
                .phys_addr(),
            res
        );
        unlink(name).unwrap();
    }

    fn test_map_multiple_pages(flags: VMFileMappingFlags) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, 0, fh2.size(), flags)
            .expect("Failed to create new VMFileMapping");

        for i in 0..4 {
            let res = vm
                .map(i * PAGE_SIZE)
                .expect("Mapping of VMFileMapping page failed");

            assert_eq!(
                fh2.mapping(i * PAGE_SIZE)
                    .expect("Failed to get file page mapping")
                    .phys_addr(),
                res
            );
        }
        unlink(name).unwrap();
    }

    fn test_map_unaligned_file_size(flags: VMFileMappingFlags) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_5000b_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, 0, fh2.size(), flags)
            .expect("Failed to create new VMFileMapping");

        assert_eq!(vm.mapping_size(), PAGE_SIZE * 2);
        assert_eq!(vm.pages.len(), 2);

        for i in 0..2 {
            let res = vm
                .map(i * PAGE_SIZE)
                .expect("Mapping of first VMFileMapping page failed");

            assert_eq!(
                fh2.mapping(i * PAGE_SIZE)
                    .expect("Failed to get file page mapping")
                    .phys_addr(),
                res
            );
        }
        unlink(name).unwrap();
    }

    fn test_map_non_zero_offset(flags: VMFileMappingFlags) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, 2 * PAGE_SIZE, PAGE_SIZE, flags)
            .expect("Failed to create new VMFileMapping");

        assert_eq!(vm.mapping_size(), PAGE_SIZE);
        assert_eq!(vm.pages.len(), 1);

        let res = vm
            .map(0)
            .expect("Mapping of first VMFileMapping page failed");

        assert_eq!(
            fh2.mapping(2 * PAGE_SIZE)
                .expect("Failed to get file page mapping")
                .phys_addr(),
            res
        );
        unlink(name).unwrap();
    }

    #[test]
    fn test_map_first_page_readonly() {
        test_map_first_page(VMFileMappingFlags::Read)
    }

    #[test]
    fn test_map_multiple_pages_readonly() {
        test_map_multiple_pages(VMFileMappingFlags::Read)
    }

    #[test]
    fn test_map_unaligned_file_size_readonly() {
        test_map_unaligned_file_size(VMFileMappingFlags::Read)
    }

    #[test]
    fn test_map_non_zero_offset_readonly() {
        test_map_non_zero_offset(VMFileMappingFlags::Read)
    }

    #[test]
    fn test_map_first_page_readwrite() {
        test_map_first_page(VMFileMappingFlags::Write)
    }

    #[test]
    fn test_map_multiple_pages_readwrite() {
        test_map_multiple_pages(VMFileMappingFlags::Write)
    }

    #[test]
    fn test_map_unaligned_file_size_readwrite() {
        test_map_unaligned_file_size(VMFileMappingFlags::Write)
    }

    #[test]
    fn test_map_non_zero_offset_readwrite() {
        test_map_non_zero_offset(VMFileMappingFlags::Write)
    }
}
