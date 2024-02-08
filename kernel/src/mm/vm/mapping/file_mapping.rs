// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::slice::from_raw_parts_mut;

#[cfg(not(test))]
use alloc::sync::Arc;

use alloc::vec::Vec;

#[cfg(not(test))]
use super::{Mapping, VMPhysMem};

use super::{RawAllocMapping, VMPageFaultResolution, VirtualMapping};
#[cfg(test)]
use crate::address::Address;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::mm::vm::VMR;
use crate::mm::PageRef;
use crate::mm::{pagetable::PTEntryFlags, PAGE_SIZE};
use crate::types::{PageSize, PAGE_SHIFT};
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

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        self.0.map(offset)
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        PTEntryFlags::task_data()
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
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

#[cfg(not(test))]
fn copy_page(
    vmr: &VMR,
    file: &FileHandle,
    offset: usize,
    paddr_dst: PhysAddr,
    page_size: PageSize,
) -> Result<(), SvsmError> {
    let page_size = usize::from(page_size);
    let temp_map = VMPhysMem::new(paddr_dst, page_size, true);
    let vaddr_new_page = vmr.insert(Arc::new(Mapping::new(temp_map)?))?;
    let slice = unsafe { from_raw_parts_mut(vaddr_new_page.as_mut_ptr::<u8>(), page_size) };
    file.seek(offset);
    file.read(slice)?;
    vmr.remove(vaddr_new_page)?;
    Ok(())
}

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
        if let Some(write_copy) = &self.write_copy {
            if let Some(write_addr) = write_copy.map(offset) {
                return Some(write_addr);
            };
        }
        self.pages[page_index].as_ref().map(|p| p.phys_addr())
    }

    fn pt_flags(&self, offset: usize) -> PTEntryFlags {
        match self.permission {
            VMFileMappingPermission::Read => PTEntryFlags::task_data_ro(),
            VMFileMappingPermission::Write => {
                if let Some(write_copy) = &self.write_copy {
                    if write_copy.get_alloc().present(offset) {
                        PTEntryFlags::task_data()
                    } else {
                        PTEntryFlags::task_data_ro()
                    }
                } else {
                    PTEntryFlags::task_data_ro()
                }
            }
            VMFileMappingPermission::Execute => PTEntryFlags::task_exec(),
        }
    }

    fn handle_page_fault(
        &mut self,
        vmr: &VMR,
        offset: usize,
        write: bool,
    ) -> Result<VMPageFaultResolution, SvsmError> {
        let page_size = self.page_size();
        let page_size_bytes = usize::from(page_size);

        if !write {
            return Err(SvsmError::Mem);
        }

        let Some(write_copy) = self.write_copy.as_mut() else {
            return Err(SvsmError::Mem);
        };

        // This is a writeable region with copy-on-write access. The
        // page fault will have occurred because the page has not yet
        // been allocated. Allocate a page and copy the readonly source
        // page into the new writeable page.
        let offset_aligned = offset & !(page_size_bytes - 1);
        write_copy.get_alloc_mut().alloc_page(offset_aligned)?;
        let paddr_new_page = write_copy.map(offset_aligned).ok_or(SvsmError::Mem)?;
        copy_page(vmr, &self.file, offset_aligned, paddr_new_page, page_size)?;
        Ok(VMPageFaultResolution {
            paddr: paddr_new_page,
            flags: PTEntryFlags::task_data(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::VirtAddr,
        fs::{create, open, unlink, TestFileSystemGuard},
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
        let vm = VMFileMapping::new(fh, 0, 512, VMFileMappingPermission::Read)
            .expect("Failed to create new VMFileMapping");
        assert_eq!(vm.mapping_size(), PAGE_SIZE);
        assert_eq!(vm.permission, VMFileMappingPermission::Read);
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
        let fh2 = open(name).unwrap();
        let vm = VMFileMapping::new(
            fh,
            offset,
            fh2.size() - offset,
            VMFileMappingPermission::Read,
        );
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_size_too_large() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open(name).unwrap();
        let vm = VMFileMapping::new(fh, 0, fh2.size() + 1, VMFileMappingPermission::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_offset_overflow() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open(name).unwrap();
        let vm = VMFileMapping::new(fh, PAGE_SIZE, fh2.size(), VMFileMappingPermission::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    fn test_map_first_page(permission: VMFileMappingPermission) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_512b_test_file();
        let vm =
            VMFileMapping::new(fh, 0, 512, permission).expect("Failed to create new VMFileMapping");

        let res = vm
            .map(0)
            .expect("Mapping of first VMFileMapping page failed");

        let fh2 = open(name).unwrap();
        assert_eq!(
            fh2.mapping(0)
                .expect("Failed to get file page mapping")
                .phys_addr(),
            res
        );
        unlink(name).unwrap();
    }

    fn test_map_multiple_pages(permission: VMFileMappingPermission) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open(name).unwrap();
        let vm = VMFileMapping::new(fh, 0, fh2.size(), permission)
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

    fn test_map_unaligned_file_size(permission: VMFileMappingPermission) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_5000b_test_file();
        let fh2 = open(name).unwrap();
        let vm = VMFileMapping::new(fh, 0, fh2.size(), permission)
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

    fn test_map_non_zero_offset(permission: VMFileMappingPermission) {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open(name).unwrap();
        let vm = VMFileMapping::new(fh, 2 * PAGE_SIZE, PAGE_SIZE, permission)
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
        test_map_first_page(VMFileMappingPermission::Read)
    }

    #[test]
    fn test_map_multiple_pages_readonly() {
        test_map_multiple_pages(VMFileMappingPermission::Read)
    }

    #[test]
    fn test_map_unaligned_file_size_readonly() {
        test_map_unaligned_file_size(VMFileMappingPermission::Read)
    }

    #[test]
    fn test_map_non_zero_offset_readonly() {
        test_map_non_zero_offset(VMFileMappingPermission::Read)
    }

    #[test]
    fn test_map_first_page_readwrite() {
        test_map_first_page(VMFileMappingPermission::Write)
    }

    #[test]
    fn test_map_multiple_pages_readwrite() {
        test_map_multiple_pages(VMFileMappingPermission::Write)
    }

    #[test]
    fn test_map_unaligned_file_size_readwrite() {
        test_map_unaligned_file_size(VMFileMappingPermission::Write)
    }

    #[test]
    fn test_map_non_zero_offset_readwrite() {
        test_map_non_zero_offset(VMFileMappingPermission::Write)
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    fn test_handle_page_fault() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open(name).unwrap();
        let mut vm = VMFileMapping::new(fh, 0, fh2.size(), VMFileMappingPermission::Write)
            .expect("Failed to create new VMFileMapping");

        let vmr = VMR::new(
            VirtAddr::from(0usize),
            VirtAddr::from(16usize * PAGE_SIZE),
            PTEntryFlags::data(),
        );
        let res = vm
            .handle_page_fault(&vmr, PAGE_SIZE, true)
            .expect("handle_page_fault() failed");
        assert!(vm.write_copy.is_some());
        assert_eq!(
            vm.write_copy.as_ref().unwrap().0.mapping_size(),
            vm.mapping_size()
        );
        assert_eq!(
            res.paddr,
            vm.write_copy
                .as_ref()
                .unwrap()
                .0
                .map(PAGE_SIZE)
                .expect("Page not allocated")
        );
        // create_16k_test_file() populates the first byte of each 4K page with
        // the page number. We can use this to check if the copy from the file
        // page to the writeable page worked correctly.
        assert_eq!(unsafe { (res.paddr.bits() as *const u8).read() }, 1);

        assert_eq!(
            vm.map(PAGE_SIZE).expect("Failed to map file page"),
            res.paddr
        );
        unlink(name).unwrap();
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    fn test_handle_page_fault_unaligned_addr() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open(name).unwrap();
        let mut vm = VMFileMapping::new(fh, 0, fh2.size(), VMFileMappingPermission::Write)
            .expect("Failed to create new VMFileMapping");

        let vmr = VMR::new(
            VirtAddr::from(0usize),
            VirtAddr::from(16usize * PAGE_SIZE),
            PTEntryFlags::data(),
        );
        let res = vm
            .handle_page_fault(&vmr, PAGE_SIZE * 2 + 1, true)
            .expect("handle_page_fault() failed");
        assert_eq!(
            res.paddr,
            vm.write_copy
                .as_ref()
                .unwrap()
                .0
                .map(PAGE_SIZE * 2)
                .expect("Page not allocated")
        );
        // create_16k_test_file() populates the first byte of each 4K page with
        // the page number. We can use this to check if the copy from the file
        // page to the writeable page worked correctly.
        assert_eq!(unsafe { (res.paddr.bits() as *const u8).read() }, 2);

        assert_eq!(
            vm.map(PAGE_SIZE * 2).expect("Failed to map file page"),
            res.paddr
        );
        unlink(name).unwrap();
    }
}
