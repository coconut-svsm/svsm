// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{Mapping, VMPageFaultResolution, VirtualMapping};
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fs::{FileHandle, FsError};
use crate::mm::PageRef;
use crate::mm::vm::{VMFlags, VMR};
use crate::mm::{PAGE_SIZE, pagetable::PTEntryFlags};
use crate::types::PAGE_SHIFT;
use crate::utils::align_up;

/// Map view of a ramfs file into virtual memory
#[derive(Debug)]
pub struct VMFileMapping {
    /// The size of the mapping in bytes
    size: usize,

    /// The flags to apply to the virtual mapping
    flags: VMFlags,

    /// The effective page-table flags of the mapping, derived from its flags
    prot: PTEntryFlags,

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
    ///   reference to the file until it is dropped.
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
        flags: VMFlags,
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
        if (flags.contains(VMFlags::Write) && !flags.contains(VMFlags::Private) && !file.writable())
            || (flags.contains(VMFlags::Read) && !file.readable())
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
            if flags.contains(VMFlags::Private) {
                pages.push(page_ref.try_copy_page()?);
            } else {
                pages.push(page_ref);
            }
        }
        Ok(Self {
            size: page_size,
            flags,
            prot: flags.page_prot(),
            pages,
        })
    }

    /// Clones the page references covering `range`, for use when splitting
    /// the mapping or changing its access.
    ///
    /// # Returns
    ///
    /// The cloned page references, `Err(SvsmError::Mem)` if they could not be
    /// allocated.
    fn clone_pages<R>(&self, range: R) -> Result<Vec<PageRef>, SvsmError>
    where
        R: core::slice::SliceIndex<[PageRef], Output = [PageRef]>,
    {
        let src = &self.pages[range];
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(src.len())
            .map_err(|_| SvsmError::Mem)?;
        pages.extend_from_slice(src);
        Ok(pages)
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
        self.prot
    }

    fn split_at(&self, offset: usize) -> Result<(Mapping, Mapping), SvsmError> {
        if offset == 0 || offset >= self.size || offset % PAGE_SIZE != 0 {
            return Err(SvsmError::Mem);
        }

        let index = offset >> PAGE_SHIFT;
        let head = Self {
            size: offset,
            flags: self.flags,
            prot: self.prot,
            pages: self.clone_pages(..index)?,
        };
        let tail = Self {
            size: self.size - offset,
            flags: self.flags,
            prot: self.prot,
            pages: self.clone_pages(index..)?,
        };

        Ok((Arc::new(head), Arc::new(tail)))
    }

    fn set_access(&self, access: VMFlags) -> Result<Mapping, SvsmError> {
        let flags = self.flags.with_access(access);

        Ok(Arc::new(Self {
            size: self.size,
            flags,
            prot: self.prot.with_prot(flags.page_prot()),
            pages: self.clone_pages(..)?,
        }))
    }

    fn handle_page_fault(
        &self,
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
        fs::{TestFileSystemGuard, create, open_rw, unlink},
        mm::alloc::{DEFAULT_TEST_MEMORY_SIZE, TestRootMem},
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
    fn test_split_at() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let vm = VMFileMapping::new(&fh, 0, 4 * PAGE_SIZE, VMFlags::Write)
            .expect("Failed to create new VMFileMapping");

        let (head, tail) = vm.split_at(PAGE_SIZE).expect("Failed to split");
        assert_eq!(head.mapping_size(), PAGE_SIZE);
        assert_eq!(tail.mapping_size(), 3 * PAGE_SIZE);

        // Both halves keep mapping the pages they cover, so that the same
        // offset of the original mapping still resolves to the same page.
        assert_eq!(head.map(0), vm.map(0));
        for i in 0..3 {
            assert_eq!(tail.map(i * PAGE_SIZE), vm.map((i + 1) * PAGE_SIZE));
        }

        // Nothing is mapped beyond the end of either half.
        assert!(head.map(PAGE_SIZE).is_none());
        assert!(tail.map(3 * PAGE_SIZE).is_none());

        unlink(name).unwrap();
    }

    #[test]
    fn test_split_at_invalid_offset() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let vm = VMFileMapping::new(&fh, 0, 4 * PAGE_SIZE, VMFlags::Write)
            .expect("Failed to create new VMFileMapping");

        // Splitting must leave two non-empty mappings, at a page boundary.
        assert!(vm.split_at(0).is_err());
        assert!(vm.split_at(4 * PAGE_SIZE).is_err());
        assert!(vm.split_at(PAGE_SIZE / 2).is_err());

        unlink(name).unwrap();
    }

    #[test]
    fn test_set_access() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let vm = VMFileMapping::new(&fh, 0, 4 * PAGE_SIZE, VMFlags::Write)
            .expect("Failed to create new VMFileMapping");
        assert!(vm.pt_flags(0).contains(PTEntryFlags::WRITABLE));

        let ro = vm.set_access(VMFlags::Read).expect("Failed to set access");
        assert!(!ro.pt_flags(0).contains(PTEntryFlags::WRITABLE));
        // The original is left untouched, and the new mapping covers the
        // same pages.
        assert!(vm.pt_flags(0).contains(PTEntryFlags::WRITABLE));
        assert_eq!(ro.mapping_size(), vm.mapping_size());
        for i in 0..4 {
            assert_eq!(ro.map(i * PAGE_SIZE), vm.map(i * PAGE_SIZE));
        }

        // The access is set, not reduced, so it can be granted again.
        let rw = ro.set_access(VMFlags::Write).expect("Failed to set access");
        assert!(rw.pt_flags(0).contains(PTEntryFlags::WRITABLE));

        unlink(name).unwrap();
    }

    #[test]
    fn test_set_access_preserves_other_flags() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let mut vm = VMFileMapping::new(&fh, 0, 4 * PAGE_SIZE, VMFlags::Write)
            .expect("Failed to create new VMFileMapping");

        // Flags not describing access survive a change of access.
        vm.prot |= PTEntryFlags::ACCESSED;
        let ro = vm.set_access(VMFlags::Read).expect("Failed to set access");
        assert!(ro.pt_flags(0).contains(PTEntryFlags::ACCESSED));
        assert!(!ro.pt_flags(0).contains(PTEntryFlags::WRITABLE));

        unlink(name).unwrap();
    }

    #[test]
    fn test_create_mapping() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_512b_test_file();
        let vm = VMFileMapping::new(&fh, 0, 512, VMFlags::Read)
            .expect("Failed to create new VMFileMapping");
        assert_eq!(vm.mapping_size(), PAGE_SIZE);
        assert!(vm.flags.contains(VMFlags::Read));
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
        let vm = VMFileMapping::new(&fh, offset, fh2.size() - offset, VMFlags::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_size_too_large() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, 0, fh2.size() + 1, VMFlags::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    #[test]
    fn test_create_offset_overflow() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        let (fh, name) = create_16k_test_file();
        let fh2 = open_rw(name).unwrap();
        let vm = VMFileMapping::new(&fh, PAGE_SIZE, fh2.size(), VMFlags::Read);
        assert!(vm.is_err());
        unlink(name).unwrap();
    }

    fn test_map_first_page(flags: VMFlags) {
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

    fn test_map_multiple_pages(flags: VMFlags) {
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

    fn test_map_unaligned_file_size(flags: VMFlags) {
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

    fn test_map_non_zero_offset(flags: VMFlags) {
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
        test_map_first_page(VMFlags::Read)
    }

    #[test]
    fn test_map_multiple_pages_readonly() {
        test_map_multiple_pages(VMFlags::Read)
    }

    #[test]
    fn test_map_unaligned_file_size_readonly() {
        test_map_unaligned_file_size(VMFlags::Read)
    }

    #[test]
    fn test_map_non_zero_offset_readonly() {
        test_map_non_zero_offset(VMFlags::Read)
    }

    #[test]
    fn test_map_first_page_readwrite() {
        test_map_first_page(VMFlags::Write)
    }

    #[test]
    fn test_map_multiple_pages_readwrite() {
        test_map_multiple_pages(VMFlags::Write)
    }

    #[test]
    fn test_map_unaligned_file_size_readwrite() {
        test_map_unaligned_file_size(VMFlags::Write)
    }

    #[test]
    fn test_map_non_zero_offset_readwrite() {
        test_map_non_zero_offset(VMFlags::Write)
    }
}
