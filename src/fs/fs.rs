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

struct RawFileHandle {
    file: Arc<dyn File>,
    current: usize,
}

impl RawFileHandle {
    pub fn new(file: &Arc<dyn File>) -> Self {
        RawFileHandle {
            file: file.clone(),
            current: 0,
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        let result = self.file.read(buf, self.current);
        if let Ok(v) = result {
            self.current += v;
        }
        result
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        let result = self.file.write(buf, self.current);
        if let Ok(num) = result {
            self.current += num;
        }
        result
    }

    pub fn truncate(&mut self, offset: usize) -> Result<usize, SvsmError> {
        self.file.truncate(offset)
    }

    pub fn seek(&mut self, pos: usize) {
        self.current = min(pos, self.file.size());
    }

    pub fn size(&self) -> usize {
        self.file.size()
    }
}

pub struct FileHandle {
    // Use a SpinLock here because the read operation also needs to be mutable
    // (changes file pointer). Parallel reads are still possible with multiple
    // file handles
    handle: SpinLock<RawFileHandle>,
}

unsafe impl Sync for FileHandle {}

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

struct SvsmFs {
    root: Option<Arc<RamDirectory>>,
}

unsafe impl Sync for SvsmFs {}

impl SvsmFs {
    pub const fn new() -> Self {
        SvsmFs { root: None }
    }

    pub fn initialize(&mut self, root: &Arc<RamDirectory>) {
        assert!(!self.initialized());
        self.root = Some(root.clone());
    }

    #[cfg(test)]
    pub fn uninitialize(&mut self) {
        self.root = None;
    }

    pub fn initialized(&self) -> bool {
        self.root.is_some()
    }

    pub fn root_dir(&self) -> Arc<dyn Directory> {
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

fn split_path_allow_empty(path: &str) -> Vec<&str> {
    path.split('/').filter(|x| !x.is_empty()).collect()
}

fn split_path(path: &str) -> Result<Vec<&str>, SvsmError> {
    let path_items = split_path_allow_empty(path);

    if path_items.is_empty() {
        return Err(SvsmError::FileSystem(FsError::inval()));
    }

    Ok(path_items)
}

fn walk_path(path_items: &[&str]) -> Result<Arc<dyn Directory>, SvsmError> {
    let mut current_dir = unsafe { FS_ROOT.root_dir() };

    for item in path_items.iter() {
        let dir_name = FileName::from(*item);
        let dir_entry = current_dir.lookup_entry(dir_name)?;
        current_dir = match dir_entry {
            DirEntry::File(_) => return Err(SvsmError::FileSystem(FsError::file_not_found())),
            DirEntry::Directory(dir) => dir,
        };
    }

    Ok(current_dir)
}

fn walk_path_create(path_items: &[&str]) -> Result<Arc<dyn Directory>, SvsmError> {
    let mut current_dir = unsafe { FS_ROOT.root_dir() };

    for item in path_items.iter() {
        let dir_name = FileName::from(*item);
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
    let file_name = FileName::from(path_items.pop().unwrap());
    let current_dir = walk_path(&path_items)?;

    let dir_entry = current_dir.lookup_entry(file_name)?;

    match dir_entry {
        DirEntry::Directory(_) => Err(SvsmError::FileSystem(FsError::file_not_found())),
        DirEntry::File(f) => Ok(FileHandle::new(&f)),
    }
}

pub fn create(path: &str) -> Result<FileHandle, SvsmError> {
    let mut path_items = split_path(path)?;
    let file_name = FileName::from(path_items.pop().unwrap());
    let current_dir = walk_path(&path_items)?;
    let file = current_dir.create_file(file_name)?;

    Ok(FileHandle::new(&file))
}

/// Creates a file with all sub-directories
pub fn create_all(path: &str) -> Result<FileHandle, SvsmError> {
    let mut path_items = split_path(path)?;
    let file_name = FileName::from(path_items.pop().unwrap());
    let current_dir = walk_path_create(&path_items)?;

    if file_name.length() == 0 {
        return Err(SvsmError::FileSystem(FsError::inval()));
    }

    let file = current_dir.create_file(file_name)?;

    Ok(FileHandle::new(&file))
}

pub fn mkdir(path: &str) -> Result<(), SvsmError> {
    let mut path_items = split_path(path)?;
    let dir_name = FileName::from(path_items.pop().unwrap());
    let current_dir = walk_path(&path_items)?;

    current_dir.create_directory(dir_name)?;

    Ok(())
}

pub fn unlink(path: &str) -> Result<(), SvsmError> {
    let mut path_items = split_path(path)?;
    let entry_name = FileName::from(path_items.pop().unwrap());
    let dir = walk_path(&path_items)?;

    dir.unlink(entry_name)
}

pub fn list_dir(path: &str) -> Result<Vec<FileName>, SvsmError> {
    let items = split_path_allow_empty(path);
    let dir = walk_path(&items)?;
    Ok(dir.list())
}

pub fn read(fh: &FileHandle, buf: &mut [u8]) -> Result<usize, SvsmError> {
    fh.read(buf)
}

pub fn write(fh: &FileHandle, buf: &mut [u8]) -> Result<usize, SvsmError> {
    fh.write(buf)
}

pub fn seek(fh: &FileHandle, pos: usize) {
    fh.seek(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::alloc::{destroy_test_root_mem, setup_test_root_mem, DEFAULT_TEST_MEMORY_SIZE};

    #[test]
    fn create_dir() {
        let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create file - should fail as directory does not exist yet
        assert!(create("test1/file1").is_err());

        // Create directory
        assert!(mkdir("test1").is_ok());

        // Check double-create
        assert!(mkdir("test1").is_err());

        // Check if it appears in the listing
        let root_list = list_dir("");
        assert!(root_list.is_ok());
        assert_eq!(root_list.unwrap(), [FileName::from("test1")]);

        // Try again - should succeed now
        assert!(create("test1/file1").is_ok());

        uninitialize_fs();
        destroy_test_root_mem(test_mem_lock);
    }

    #[test]
    fn create_and_unlink_file() {
        let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        assert!(create("test1").is_ok());

        // Check if it appears in the listing
        let root_list = list_dir("");
        assert!(root_list.is_ok());
        assert_eq!(root_list.unwrap(), [FileName::from("test1")]);

        // Try creating again as file - should fail
        assert!(create("test1").is_err());

        // Try creating again as directory - should fail
        assert!(mkdir("test1").is_err());

        // Try creating again as directory - should fail
        assert!(mkdir("test2").is_ok());

        // Unlink file
        assert!(unlink("test1").is_ok());

        // Check if it is removed from the listing
        let root_list = list_dir("");
        assert!(root_list.is_ok());
        assert_eq!(root_list.unwrap(), [FileName::from("test2")]);

        uninitialize_fs();
        destroy_test_root_mem(test_mem_lock);
    }

    #[test]
    fn create_sub_dir() {
        let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create file - should fail as directory does not exist yet
        assert!(create("test1/test2/file1").is_err());

        // Create directory
        assert!(mkdir("test1").is_ok());

        // Create sub-directory
        assert!(mkdir("test1/test2").is_ok());

        // Check if it appears in the listing
        let list = list_dir("test1/");
        assert!(list.is_ok());
        assert_eq!(list.unwrap(), [FileName::from("test2")]);

        // Try again - should succeed now
        assert!(create("test1/test2/file1").is_ok());

        // Check if it appears in the listing
        let list = list_dir("test1/test2/");
        assert!(list.is_ok());
        assert_eq!(list.unwrap(), [FileName::from("file1")]);

        uninitialize_fs();
        destroy_test_root_mem(test_mem_lock);
    }

    #[test]
    fn test_unlink() {
        let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create directory
        assert!(mkdir("test1").is_ok());

        // Creating files
        assert!(create("test1/file1").is_ok());
        assert!(create("test1/file2").is_ok());

        // Check if they appears in the listing
        let list = list_dir("test1");
        assert!(list.is_ok());
        assert_eq!(
            list.unwrap(),
            [FileName::from("file1"), FileName::from("file2")]
        );

        // Unlink non-existent file
        assert!(unlink("test2").is_err());

        // Unlink existing file
        assert!(unlink("test1/file1").is_ok());

        // Check if it is removed from the listing
        let list = list_dir("test1");
        assert!(list.is_ok());
        assert_eq!(list.unwrap(), [FileName::from("file2")]);

        uninitialize_fs();
        destroy_test_root_mem(test_mem_lock);
    }

    #[test]
    fn test_open_read_write_seek() {
        let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Create directory
        assert!(mkdir("test1").is_ok());

        // Try again - should succeed now
        assert!(create("test1/file1").is_ok());

        // Try to open non-existent file
        assert!(open("test1/file2").is_err());

        let result = open("test1/file1");
        assert!(result.is_ok());

        let fh = result.unwrap();
        assert!(fh.size() == 0);

        let mut buf: [u8; 512] = [0xff; 512];
        let result = write(&fh, &mut buf);
        assert_eq!(result.unwrap(), 512);

        assert_eq!(fh.size(), 512);

        fh.seek(256);
        let mut buf2: [u8; 512] = [0xcc; 512];
        let result = write(&fh, &mut buf2);
        assert!(result.is_ok());

        assert_eq!(fh.size(), 768);

        let mut buf3: [u8; 1024] = [0; 1024];
        fh.seek(0);
        let result = read(&fh, &mut buf3);
        assert_eq!(result.unwrap(), 768);

        for i in 0..buf3.len() {
            let expected: u8 = if i < 256 {
                0xff
            } else if i < 768 {
                0xcc
            } else {
                0x0
            };
            assert!(buf3[i] == expected);
        }

        drop(fh);
        uninitialize_fs();
        destroy_test_root_mem(test_mem_lock);
    }

    #[test]
    fn test_multiple_file_handles() {
        let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
        initialize_fs();

        // Try again - should succeed now
        let result = create("file");
        assert!(result.is_ok());

        let fh1 = result.unwrap();
        assert_eq!(fh1.size(), 0);

        let buf1: [u8; 6144] = [0xff; 6144];
        let result = fh1.write(&buf1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 6144);
        assert_eq!(fh1.size(), 6144);

        let result = open("file");
        assert!(result.is_ok());

        let fh2 = result.unwrap();
        assert_eq!(fh2.size(), 6144);

        let mut buf2: [u8; 4096] = [0; 4096];
        let result = fh2.read(&mut buf2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 4096);

        for i in 0..buf2.len() {
            assert_eq!(buf2[i], 0xff);
        }

        assert!(fh1.truncate(2048).is_ok());

        let result = fh2.read(&mut buf2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        drop(fh2);
        drop(fh1);
        uninitialize_fs();
        destroy_test_root_mem(test_mem_lock);
    }
}
