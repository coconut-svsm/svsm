// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::ramfs::RamDirectory;
use super::*;

use crate::error::SvsmError;
use crate::locking::SpinLock;

use core::cmp::min;

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Debug)]
struct RawFileHandle {
    file: Arc<dyn File>,
    current: usize,
}

impl RawFileHandle {
    fn new(file: &Arc<dyn File>) -> Self {
        RawFileHandle {
            file: file.clone(),
            current: 0,
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        let result = self.file.read(buf, self.current);
        if let Ok(v) = result {
            self.current += v;
        }
        result
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        let result = self.file.write(buf, self.current);
        if let Ok(num) = result {
            self.current += num;
        }
        result
    }

    fn truncate(&mut self, offset: usize) -> Result<usize, SvsmError> {
        self.file.truncate(offset)
    }

    fn seek(&mut self, pos: usize) {
        self.current = min(pos, self.file.size());
    }

    fn size(&self) -> usize {
        self.file.size()
    }
}

#[derive(Debug)]
pub struct FileHandle {
    // Use a SpinLock here because the read operation also needs to be mutable
    // (changes file pointer). Parallel reads are still possible with multiple
    // file handles
    handle: SpinLock<RawFileHandle>,
}

impl FileHandle {
    pub fn new(file: &Arc<dyn File>) -> Self {
        FileHandle {
            handle: SpinLock::new(RawFileHandle::new(file)),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        self.handle.lock().read(buf)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, SvsmError> {
        self.handle.lock().write(buf)
    }

    pub fn truncate(&self, offset: usize) -> Result<usize, SvsmError> {
        self.handle.lock().truncate(offset)
    }

    pub fn seek(&self, pos: usize) {
        self.handle.lock().seek(pos);
    }

    pub fn size(&self) -> usize {
        self.handle.lock().size()
    }
}

#[derive(Debug)]
struct SvsmFs {
    root: Option<Arc<RamDirectory>>,
}

impl SvsmFs {
    const fn new() -> Self {
        SvsmFs { root: None }
    }

    fn initialize(&mut self, root: &Arc<RamDirectory>) {
        assert!(!self.initialized());
        self.root = Some(root.clone());
    }

    #[cfg(test)]
    fn uninitialize(&mut self) {
        self.root = None;
    }

    fn initialized(&self) -> bool {
        self.root.is_some()
    }

    fn root_dir(&self) -> Arc<dyn Directory> {
        assert!(self.initialized());
        self.root.as_ref().unwrap().clone()
    }
}

static mut FS_ROOT: SvsmFs = SvsmFs::new();

pub fn initialize_fs() {
    let root_dir = Arc::new(RamDirectory::new());
    unsafe {
        FS_ROOT.initialize(&root_dir);
    }
}

#[cfg(test)]
fn uninitialize_fs() {
    unsafe {
        FS_ROOT.uninitialize();
    }
}

fn split_path_allow_empty(path: &str) -> impl Iterator<Item = &str> + DoubleEndedIterator {
    path.split('/').filter(|x| !x.is_empty())
}

fn split_path(path: &str) -> Result<impl Iterator<Item = &str> + DoubleEndedIterator, SvsmError> {
    let mut path_items = split_path_allow_empty(path).peekable();
    path_items
        .peek()
        .ok_or(SvsmError::FileSystem(FsError::inval()))?;
    Ok(path_items)
}

fn walk_path<'a, I>(path_items: I) -> Result<Arc<dyn Directory>, SvsmError>
where
    I: Iterator<Item = &'a str>,
{
    let mut current_dir = unsafe { FS_ROOT.root_dir() };

    for item in path_items {
        let dir_name = FileName::from(item);
        let dir_entry = current_dir.lookup_entry(dir_name)?;
        current_dir = match dir_entry {
            DirEntry::File(_) => return Err(SvsmError::FileSystem(FsError::file_not_found())),
            DirEntry::Directory(dir) => dir,
        };
    }

    Ok(current_dir)
}

fn walk_path_create<'a, I>(path_items: I) -> Result<Arc<dyn Directory>, SvsmError>
where
    I: Iterator<Item = &'a str>,
{
    let mut current_dir = unsafe { FS_ROOT.root_dir() };

    for item in path_items {
        let dir_name = FileName::from(item);
        let lookup = current_dir.lookup_entry(dir_name);
        let dir_entry = match lookup {
            Ok(entry) => entry,
            Err(_) => DirEntry::Directory(current_dir.create_directory(dir_name)?),
        };
        current_dir = match dir_entry {
            DirEntry::File(_) => return Err(SvsmError::FileSystem(FsError::file_not_found())),
            DirEntry::Directory(dir) => dir,
        };
    }

    Ok(current_dir)
}

pub fn open(path: &str) -> Result<FileHandle, SvsmError> {
    let mut path_items = split_path(path)?;
    let file_name = FileName::from(path_items.next_back().unwrap());
    let current_dir = walk_path(path_items)?;

    let dir_entry = current_dir.lookup_entry(file_name)?;

    match dir_entry {
        DirEntry::Directory(_) => Err(SvsmError::FileSystem(FsError::file_not_found())),
        DirEntry::File(f) => Ok(FileHandle::new(&f)),
    }
}

pub fn create(path: &str) -> Result<FileHandle, SvsmError> {
    let mut path_items = split_path(path)?;
    let file_name = FileName::from(path_items.next_back().unwrap());
    let current_dir = walk_path(path_items)?;
    let file = current_dir.create_file(file_name)?;

    Ok(FileHandle::new(&file))
}

/// Creates a file with all sub-directories
pub fn create_all(path: &str) -> Result<FileHandle, SvsmError> {
    let mut path_items = split_path(path)?;
    let file_name = FileName::from(path_items.next_back().unwrap());
    let current_dir = walk_path_create(path_items)?;

    if file_name.length() == 0 {
        return Err(SvsmError::FileSystem(FsError::inval()));
    }

    let file = current_dir.create_file(file_name)?;

    Ok(FileHandle::new(&file))
}

pub fn mkdir(path: &str) -> Result<(), SvsmError> {
    let mut path_items = split_path(path)?;
    let dir_name = FileName::from(path_items.next_back().unwrap());
    let current_dir = walk_path(path_items)?;

    current_dir.create_directory(dir_name)?;

    Ok(())
}

pub fn unlink(path: &str) -> Result<(), SvsmError> {
    let mut path_items = split_path(path)?;
    let entry_name = FileName::from(path_items.next_back().unwrap());
    let dir = walk_path(path_items)?;

    dir.unlink(entry_name)
}

pub fn list_dir(path: &str) -> Result<Vec<FileName>, SvsmError> {
    let items = split_path_allow_empty(path);
    let dir = walk_path(items)?;
    Ok(dir.list())
}

pub fn read(fh: &FileHandle, buf: &mut [u8]) -> Result<usize, SvsmError> {
    fh.read(buf)
}

pub fn write(fh: &FileHandle, buf: &[u8]) -> Result<usize, SvsmError> {
    fh.write(buf)
}

pub fn seek(fh: &FileHandle, pos: usize) {
    fh.seek(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::alloc::{TestRootMem, DEFAULT_TEST_MEMORY_SIZE};

    #[test]
    fn create_dir() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create file - should fail as directory does not exist yet
        create("test1/file1").unwrap_err();

        // Create directory
        mkdir("test1").unwrap();

        // Check double-create
        mkdir("test1").unwrap_err();

        // Check if it appears in the listing
        let root_list = list_dir("").unwrap();
        assert_eq!(root_list, [FileName::from("test1")]);

        // Try again - should succeed now
        create("test1/file1").unwrap();

        uninitialize_fs();
    }

    #[test]
    fn create_and_unlink_file() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        create("test1").unwrap();

        // Check if it appears in the listing
        let root_list = list_dir("").unwrap();
        assert_eq!(root_list, [FileName::from("test1")]);

        // Try creating again as file - should fail
        create("test1").unwrap_err();

        // Try creating again as directory - should fail
        mkdir("test1").unwrap_err();

        // Try creating again as directory - should fail
        mkdir("test2").unwrap();

        // Unlink file
        unlink("test1").unwrap();

        // Check if it is removed from the listing
        let root_list = list_dir("").unwrap();
        assert_eq!(root_list, [FileName::from("test2")]);

        uninitialize_fs();
    }

    #[test]
    fn create_sub_dir() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create file - should fail as directory does not exist yet
        create("test1/test2/file1").unwrap_err();

        // Create directory
        mkdir("test1").unwrap();

        // Create sub-directory
        mkdir("test1/test2").unwrap();

        // Check if it appears in the listing
        let list = list_dir("test1/").unwrap();
        assert_eq!(list, [FileName::from("test2")]);

        // Try again - should succeed now
        create("test1/test2/file1").unwrap();

        // Check if it appears in the listing
        let list = list_dir("test1/test2/").unwrap();
        assert_eq!(list, [FileName::from("file1")]);

        uninitialize_fs();
    }

    #[test]
    fn test_unlink() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create directory
        mkdir("test1").unwrap();

        // Creating files
        create("test1/file1").unwrap();
        create("test1/file2").unwrap();

        // Check if they appears in the listing
        let list = list_dir("test1").unwrap();
        assert_eq!(list, [FileName::from("file1"), FileName::from("file2")]);

        // Unlink non-existent file
        unlink("test2").unwrap_err();

        // Unlink existing file
        unlink("test1/file1").unwrap();

        // Check if it is removed from the listing
        let list = list_dir("test1").unwrap();
        assert_eq!(list, [FileName::from("file2")]);

        uninitialize_fs();
    }

    #[test]
    fn test_open_read_write_seek() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create directory
        mkdir("test1").unwrap();

        // Try again - should succeed now
        create("test1/file1").unwrap();

        // Try to open non-existent file
        open("test1/file2").unwrap_err();

        let fh = open("test1/file1").unwrap();

        assert!(fh.size() == 0);

        let buf: [u8; 512] = [0xff; 512];
        let result = write(&fh, &buf).unwrap();
        assert_eq!(result, 512);

        assert_eq!(fh.size(), 512);

        fh.seek(256);
        let buf2: [u8; 512] = [0xcc; 512];
        let result = write(&fh, &buf2).unwrap();
        assert_eq!(result, 512);

        assert_eq!(fh.size(), 768);

        let mut buf3: [u8; 1024] = [0; 1024];
        fh.seek(0);
        let result = read(&fh, &mut buf3).unwrap();
        assert_eq!(result, 768);

        for (i, elem) in buf3.iter().enumerate() {
            let expected: u8 = if i < 256 {
                0xff
            } else if i < 768 {
                0xcc
            } else {
                0x0
            };
            assert!(*elem == expected);
        }

        drop(fh);
        uninitialize_fs();
    }

    #[test]
    fn test_multiple_file_handles() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Try again - should succeed now
        let fh1 = create("file").unwrap();
        assert_eq!(fh1.size(), 0);

        let buf1: [u8; 6144] = [0xff; 6144];
        let result = fh1.write(&buf1).unwrap();
        assert_eq!(result, 6144);
        assert_eq!(fh1.size(), 6144);

        let fh2 = open("file").unwrap();
        assert_eq!(fh2.size(), 6144);

        let mut buf2: [u8; 4096] = [0; 4096];
        let result = fh2.read(&mut buf2).unwrap();
        assert_eq!(result, 4096);

        for elem in &buf2 {
            assert_eq!(*elem, 0xff);
        }

        fh1.truncate(2048).unwrap();

        let result = fh2.read(&mut buf2).unwrap();
        assert_eq!(result, 0);

        drop(fh2);
        drop(fh1);
        uninitialize_fs();
    }
}
