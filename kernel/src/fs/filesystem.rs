// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::ramfs::RamDirectory;
use super::*;

use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use crate::mm::PageRef;

use core::cmp::min;

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Represents a raw file handle.
#[derive(Debug)]
struct RawFileHandle {
    file: Arc<dyn File>,
    /// current file offset for the read/write operation
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

    fn truncate(&self, offset: usize) -> Result<usize, SvsmError> {
        self.file.truncate(offset)
    }

    fn seek(&mut self, pos: usize) {
        self.current = min(pos, self.file.size());
    }

    fn size(&self) -> usize {
        self.file.size()
    }

    fn mapping(&self, offset: usize) -> Option<PageRef> {
        self.file.mapping(offset)
    }
}

/// Represents a handle used for file operations in a thread-safe manner.
#[derive(Debug)]
pub struct FileHandle {
    // Use a SpinLock here because the read operation also needs to be mutable
    // (changes file pointer). Parallel reads are still possible with multiple
    // file handles
    handle: SpinLock<RawFileHandle>,
}

impl FileHandle {
    /// Create a new file handle instance.
    pub fn new(file: &Arc<dyn File>) -> Self {
        FileHandle {
            handle: SpinLock::new(RawFileHandle::new(file)),
        }
    }

    /// Used to read contents from the file handle.
    ///
    /// # Arguments
    ///
    /// - `buf`: buffer to read the file contents to
    ///
    /// # Returns
    ///
    /// [`Result<usize, SvsmError>`]: A [`Result`] containing the number of
    /// bytes read if successful, or an [`SvsmError`] if there was a problem
    /// during the read operation.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        self.handle.lock().read(buf)
    }

    /// Used to write contents to the file handle
    ///
    /// # Arguments
    ///
    /// - `buf`: buffer which holds the contents to be written to the file.
    ///
    /// # Returns
    ///
    /// [`Result<usize, SvsmError>`]: A [`Result`] containing the number of
    /// bytes written if successful, or an [`SvsmError`] if there was a problem
    /// during the write operation.
    pub fn write(&self, buf: &[u8]) -> Result<usize, SvsmError> {
        self.handle.lock().write(buf)
    }

    /// Used to truncate the file to the specified size.
    ///
    ///  # Arguments
    ///
    ///  - `offset`: specifies the size in bytes to which the file
    ///     git  is to be truncated.
    ///
    ///  # Returns
    ///
    /// [`Result<usize, SvsmError>`]: A [`Result`] containing the size of the
    /// file after truncation if successful, or an [`SvsmError`] if there was
    /// a problem during the truncate operation.
    pub fn truncate(&self, offset: usize) -> Result<usize, SvsmError> {
        self.handle.lock().truncate(offset)
    }

    /// Used to change the current file offset.
    ///
    /// # Arguments
    ///
    /// - `pos`: intended new file offset value.
    pub fn seek(&self, pos: usize) {
        self.handle.lock().seek(pos);
    }

    /// Used to get the size of the file.
    ///
    /// # Returns
    ///
    /// Size of the file in bytes.
    pub fn size(&self) -> usize {
        self.handle.lock().size()
    }

    pub fn position(&self) -> usize {
        self.handle.lock().current
    }

    pub fn mapping(&self, offset: usize) -> Option<PageRef> {
        self.handle.lock().mapping(offset)
    }
}

/// Represents SVSM filesystem
#[derive(Debug)]
struct SvsmFs {
    root: Option<Arc<RamDirectory>>,
}

impl SvsmFs {
    const fn new() -> Self {
        SvsmFs { root: None }
    }

    /// Used to set the root directory of the SVSM filesystem.
    ///
    /// # Arguments
    ///
    /// - `root`: represents directory which is to be set
    ///   as the root of the filesystem.
    fn initialize(&mut self, root: &Arc<RamDirectory>) {
        assert!(!self.initialized());
        self.root = Some(root.clone());
    }

    #[cfg(all(any(test, fuzzing), not(test_in_svsm)))]
    fn uninitialize(&mut self) {
        self.root = None;
    }

    /// Used to check if the filesystem is initialized.
    ///
    /// # Returns
    ///
    /// [`bool`]: If the filesystem is initialized.
    fn initialized(&self) -> bool {
        self.root.is_some()
    }

    /// Used to get the root directory of the filesystem.
    ///
    /// # Returns
    ///
    /// [`Arc<dyn Directory>`]: root directory of the filesystem.
    fn root_dir(&self) -> Arc<dyn Directory> {
        assert!(self.initialized());
        self.root.as_ref().unwrap().clone()
    }
}

static FS_ROOT: RWLock<SvsmFs> = RWLock::new(SvsmFs::new());

/// Used to initialize the filesystem with an empty root directory.
pub fn initialize_fs() {
    let root_dir = Arc::new(RamDirectory::new());

    FS_ROOT.lock_write().initialize(&root_dir);
}

#[cfg(any(test, fuzzing))]
#[cfg_attr(test_in_svsm, derive(Clone, Copy))]
#[derive(Debug)]
pub struct TestFileSystemGuard;

#[cfg(any(test, fuzzing))]
impl TestFileSystemGuard {
    /// Create a test filesystem.
    ///
    /// When running as a regular test in userspace:
    ///
    ///   * Creating the struct via `setup()` will initialize an empty
    ///     filesystem.
    ///   * Dropping the struct will cause the filesystem to
    ///     uninitialize.
    ///
    /// When running inside the SVSM, creating or dropping the struct
    /// is a no-op, as the filesystem is managed by the SVSM kernel.
    #[must_use = "filesystem guard must be held for the whole test"]
    pub fn setup() -> Self {
        #[cfg(not(test_in_svsm))]
        initialize_fs();
        Self
    }
}

#[cfg(all(any(test, fuzzing), not(test_in_svsm)))]
impl Drop for TestFileSystemGuard {
    fn drop(&mut self) {
        // Uninitialize the filesystem only if running in userspace.
        FS_ROOT.lock_write().uninitialize();
    }
}

/// Used to get an iterator over all the directory and file names contained in a path.
/// Directory name or file name in the path can be an empty value.
///
///  # Argument
///
///  `path`: path to be split.
///
///  # Returns
///
///  [`impl Iterator <Item = &str> + DoubleEndedIterator`]: iterator over all the
///  directory and file names in the path.
fn split_path_allow_empty(path: &str) -> impl DoubleEndedIterator<Item = &str> {
    path.split('/').filter(|x| !x.is_empty())
}

/// Used to get an iterator over all the directory and file names contained in a path.
/// This function performs error checking.
///
/// # Argument
///
/// `path`: path to be split.
///
/// # Returns
///
///  [`impl Iterator <Item = &str> + DoubleEndedIterator`]: iterator over all the
///  directory and file names in the path.
fn split_path(path: &str) -> Result<impl DoubleEndedIterator<Item = &str>, SvsmError> {
    let mut path_items = split_path_allow_empty(path).peekable();
    path_items
        .peek()
        .ok_or(SvsmError::FileSystem(FsError::inval()))?;
    Ok(path_items)
}

/// Used to perform a walk over the items in a path while checking
/// each item is a directory.
///
/// # Argument
///
/// `path_items`: contains items in a path.
///
/// # Returns
///
/// [`Result<Arc<dyn Directory>, SvsmError>`]: [`Result`] containing the
/// directory corresponding to the path if successful, or [`SvsmError`]
/// if there is an error.
fn walk_path<'a, I>(path_items: I) -> Result<Arc<dyn Directory>, SvsmError>
where
    I: Iterator<Item = &'a str>,
{
    let fs_root = FS_ROOT.lock_read();
    let mut current_dir = fs_root.root_dir();
    drop(fs_root);

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

/// Used to perform a walk over the items in a path while checking
/// each existing item is a directory, while creating a directory
/// for each non-existing item.
///
/// # Argument
///
/// `path_items`: contains items in a path.
///
/// # Returns
///
/// [`Result<Arc<dyn Directory>, SvsmError>`]: [`Result`] containing the
/// directory corresponding to the path if successful, or [`SvsmError`]
/// if there is an error.
fn walk_path_create<'a, I>(path_items: I) -> Result<Arc<dyn Directory>, SvsmError>
where
    I: Iterator<Item = &'a str>,
{
    let fs_root = FS_ROOT.lock_read();
    let mut current_dir = fs_root.root_dir();
    drop(fs_root);

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

/// Used to open a file to get the file handle for further file operations.
///
/// # Argument
///
/// `path`: path of the file to be opened.
///
/// # Returns
///
/// [`Result<FileHandle, SvsmError>`]: [`Result`] containing the [`FileHandle`]
/// of the opened file if the file exists, [`SvsmError`] otherwise.
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

/// Used to create a file with the given path.
///
/// # Argument
///
/// `path`: path of the file to be created.
///
/// # Returns
///
/// [`Result<FileHandle, SvsmError>`]: [`Result`] containing the [`FileHandle`]
/// for the opened file if successful, [`SvsmError`] otherwise.
pub fn create(path: &str) -> Result<FileHandle, SvsmError> {
    let mut path_items = split_path(path)?;
    let file_name = FileName::from(path_items.next_back().unwrap());
    let current_dir = walk_path(path_items)?;
    let file = current_dir.create_file(file_name)?;

    Ok(FileHandle::new(&file))
}

/// Used to create a file and the missing subdirectories in the given path.
///
/// # Argument
///
/// `path`: path of the file to be created.
///
/// # Returns
///
/// [`Result<FileHandle, SvsmError>`]: [`Result`] containing the [`FileHandle`]
/// for the opened file if successful, [`SvsmError`] otherwise.
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

/// Used to create a directory with the given path.
///
/// # Argument
///
/// `path`: path of the directory to be created.
///
/// # Returns
///
/// [`Result<(), SvsmError>`]: [`Result`] containing the unit
/// value if successful,  [`SvsmError`] otherwise.
pub fn mkdir(path: &str) -> Result<(), SvsmError> {
    let mut path_items = split_path(path)?;
    let dir_name = FileName::from(path_items.next_back().unwrap());
    let current_dir = walk_path(path_items)?;

    current_dir.create_directory(dir_name)?;

    Ok(())
}

/// Used to delete a file or a directory.
///
/// # Argument
///
/// `path`: path of the file or directory to be created.
///
/// # Returns
///
/// [`Result<(), SvsmError>`]: [`Result`] containing the unit
/// value if successful,  [`SvsmError`] otherwise.
pub fn unlink(path: &str) -> Result<(), SvsmError> {
    let mut path_items = split_path(path)?;
    let entry_name = FileName::from(path_items.next_back().unwrap());
    let dir = walk_path(path_items)?;

    dir.unlink(entry_name)
}

/// Used to list the contents of a directory.
///
/// # Argument
///
/// `path`: path of the directory to be listed.
/// # Returns
///
/// [`Result<(), SvsmError>`]: [`Result`] containing the [`Vec`]
/// of directory entries if successful,  [`SvsmError`] otherwise.
pub fn list_dir(path: &str) -> Result<Vec<FileName>, SvsmError> {
    let items = split_path_allow_empty(path);
    let dir = walk_path(items)?;
    Ok(dir.list())
}

/// Used to read from a file handle.
///
/// # Arguments
///
/// - `fh`: Filehandle to be read.
/// - `buf`: buffer to read the file contents into.
///
/// # Returns
///
/// [`Result<usize, SvsmError>`]: [`Result`] containing the number
/// of bytes read if successful,  [`SvsmError`] otherwise.
pub fn read(fh: &FileHandle, buf: &mut [u8]) -> Result<usize, SvsmError> {
    fh.read(buf)
}

/// Used to write into file handle.
///
/// # Arguments
///
/// - `fh`: Filehandle to be written.
/// - `buf`: buffer containing the data to be written.
///
/// # Returns
///
/// [`Result<usize, SvsmError>`]: [`Result`] containing the number
/// of bytes written if successful,  [`SvsmError`] otherwise.
pub fn write(fh: &FileHandle, buf: &[u8]) -> Result<usize, SvsmError> {
    fh.write(buf)
}

/// Used to set the file offset
///
/// # Arguements
///
/// - `fh`: Filehandle for the seek operation.
/// - `pos`: new file offset value to be set.
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
        let _test_fs = TestFileSystemGuard::setup();

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

        // Cleanup
        unlink("test1/file1").unwrap();
        unlink("test1").unwrap();
    }

    #[test]
    fn create_and_unlink_file() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        create("test1").unwrap();

        // Check if it appears in the listing
        let root_list = list_dir("").unwrap();
        assert_eq!(root_list, [FileName::from("test1")]);

        // Try creating again as file - should fail
        create("test1").unwrap_err();

        // Try creating again as directory - should fail
        mkdir("test1").unwrap_err();

        // Try creating a different dir
        mkdir("test2").unwrap();

        // Unlink file
        unlink("test1").unwrap();

        // Check if it is removed from the listing
        let root_list = list_dir("").unwrap();
        assert_eq!(root_list, [FileName::from("test2")]);

        // Cleanup
        unlink("test2").unwrap();
    }

    #[test]
    fn create_sub_dir() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

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

        // Cleanup
        unlink("test1/test2/file1").unwrap();
        unlink("test1/test2").unwrap();
        unlink("test1/").unwrap();
    }

    #[test]
    fn test_unlink() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

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

        // Cleanup
        unlink("test1/file2").unwrap();
        unlink("test1").unwrap();
    }

    #[test]
    fn test_open_read_write_seek() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

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

        // Cleanup
        unlink("test1/file1").unwrap();
        unlink("test1").unwrap();
    }

    #[test]
    fn test_multiple_file_handles() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let _test_fs = TestFileSystemGuard::setup();

        // Create file
        let fh1 = create("file").unwrap();
        assert_eq!(fh1.size(), 0);

        let buf1: [u8; 6144] = [0xff; 6144];
        let result = fh1.write(&buf1).unwrap();
        assert_eq!(result, 6144);
        assert_eq!(fh1.size(), 6144);

        // Another handle to the same file
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

        // Cleanup
        unlink("file").unwrap();
    }
}
