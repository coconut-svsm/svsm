// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::fmt::Debug;

use crate::error::SvsmError;
use crate::mm::PageRef;
use crate::string::FixedString;
use packit::PackItError;

/// Maximum supported length for a single filename
const MAX_FILENAME_LENGTH: usize = 64;
pub type FileName = FixedString<MAX_FILENAME_LENGTH>;

/// Represents the type of error occured
/// while doing SVSM filesystem operations.
#[derive(Copy, Clone, Debug, Default)]
pub enum FsError {
    #[default]
    Inval,
    FileExists,
    FileNotFound,
    PackIt(PackItError),
}

impl From<FsError> for SvsmError {
    fn from(e: FsError) -> Self {
        Self::FileSystem(e)
    }
}

impl From<PackItError> for FsError {
    fn from(e: PackItError) -> Self {
        Self::PackIt(e)
    }
}

impl From<PackItError> for SvsmError {
    fn from(e: PackItError) -> Self {
        Self::from(FsError::from(e))
    }
}

/// Used to define methods of [`FsError`].
macro_rules! impl_fs_err {
    ($name:ident, $v:ident) => {
        pub fn $name() -> Self {
            Self::$v
        }
    };
}

impl FsError {
    impl_fs_err!(inval, Inval);
    impl_fs_err!(file_exists, FileExists);
    impl_fs_err!(file_not_found, FileNotFound);
}

/// Represents file operations
pub trait File: Debug + Send + Sync {
    /// Used to read contents of a file
    ///
    /// # Arguments
    ///
    /// - `buf`: buffer to read the file contents into.
    /// - `offset`: file offset to read from.
    ///
    /// # Returns
    ///
    /// [`Result<usize, SvsmError>`]: A [`Result`] containing the number of
    /// bytes read if successful, or an [`SvsmError`] if there was a problem
    /// during the read operation.
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError>;

    /// Used to write contents to a file
    ///
    /// # Arguments
    ///
    /// - `buf`: buffer which holds the contents to be written to the file.
    /// - `offset`: file offset to write to.
    ///
    /// # Returns
    ///
    /// [`Result<usize, SvsmError>`]: A [`Result`] containing the number of
    /// bytes written if successful, or an [`SvsmError`] if there was a problem
    /// during the write operation.
    fn write(&self, buf: &[u8], offset: usize) -> Result<usize, SvsmError>;

    /// Used to truncate the file to the specified size.
    ///
    ///  # Arguments
    ///
    ///  - `size`: specifies the size in bytes to which the file
    ///    is to be truncated.
    ///
    ///  # Returns
    ///
    /// [`Result<usize, SvsmError>`]: A [`Result`] containing the size of the
    /// file after truncation if successful, or an [`SvsmError`] if there was
    /// a problem during the truncate operation.
    fn truncate(&self, size: usize) -> Result<usize, SvsmError>;

    /// Used to get the size of the file.
    ///
    /// # Returns
    ///
    /// size of the file in bytes.
    fn size(&self) -> usize;

    /// Get reference to backing pages of the file
    ///
    /// # Arguments
    ///
    /// - `offset`: offset to the requested page in bytes
    ///
    /// # Returns
    ///
    /// [`Option<PageRef>`]: An [`Option`] with the requested page reference.
    /// `None` if the offset is not backed by a page.
    fn mapping(&self, _offset: usize) -> Option<PageRef> {
        None
    }
}

/// Represents directory operations
pub trait Directory: Debug + Send + Sync {
    /// Used to get the list of entries in the directory.
    ///
    /// # Returns
    ///
    /// A [`Vec<FileName>`] containing all the entries in the directory.
    fn list(&self) -> Vec<FileName>;

    /// Used to lookup for an entry in the directory.
    ///
    /// # Arguments
    ///
    /// - `name`: name of the entry to be looked up in the directory.
    ///
    /// # Returns
    ///
    /// [`Result<DirEntry, SvsmError>`]: A [`Result`] containing the [`DirEntry`]
    /// corresponding to the entry being looked up in the directory if present, or
    /// an [`SvsmError`] if not present.
    fn lookup_entry(&self, name: FileName) -> Result<DirEntry, SvsmError>;

    /// Used to create a new file in the directory.
    ///
    /// # Arguments
    ///
    /// - `name`: name of the file to be created.
    ///
    /// # Returns
    ///
    /// [`Result<DirEntry, SvsmError>`]: A [`Result`] containing the [`DirEntry`]
    /// of the new file created on success, or an [`SvsmError`] on failure
    fn create_file(&self, name: FileName) -> Result<Arc<dyn File>, SvsmError>;

    /// Used to create a subdirectory in the directory.
    ///
    /// # Arguments
    ///
    /// - `name`: name of the subdirectory to be created.
    ///
    /// # Returns
    ///
    /// [`Result<DirEntry, SvsmError>`]: A [`Result`] containing the [`DirEntry`]
    /// of the subdirectory created on success, or an [`SvsmError`] on failure
    fn create_directory(&self, name: FileName) -> Result<Arc<dyn Directory>, SvsmError>;

    /// Used to remove an entry from the directory.
    ///
    /// # Arguments
    ///
    /// - `name`: name of the entry to be removed from the directory.
    ///
    /// # Returns
    ///
    /// [`Result<(), SvsmError>`]: A [`Result`] containing the empty
    /// value on success, or an [`SvsmError`] on failure
    fn unlink(&self, name: FileName) -> Result<(), SvsmError>;
}

/// Represents a directory entry which could
/// either be a file or a subdirectory.
#[derive(Debug)]
pub enum DirEntry {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
}

impl DirEntry {
    /// Used to check if a [`DirEntry`] variable is a file.
    ///
    /// # Returns
    ///
    /// ['true'] if [`DirEntry`] is a file, ['false'] otherwise.
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// Used to check if a [`DirEntry`] variable is a directory.
    ///
    /// # Returns
    ///
    /// ['true'] if [`DirEntry`] is a directory, ['false'] otherwise.
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
}

impl Clone for DirEntry {
    fn clone(&self) -> Self {
        match self {
            DirEntry::File(f) => DirEntry::File(f.clone()),
            DirEntry::Directory(d) => DirEntry::Directory(d.clone()),
        }
    }
}

/// Directory entries including their names.
#[derive(Debug)]
pub struct DirectoryEntry {
    pub name: FileName,
    pub entry: DirEntry,
}

impl DirectoryEntry {
    /// Create a new [`DirectoryEntry`] instance.
    ///
    /// # Arguments
    ///
    /// - `name`: name for the entry to be created.
    /// - `entry`: [`DirEntry`] containing the file or directory details.
    ///
    /// # Returns
    ///
    /// A new [`DirectoryEntry`] instance.
    pub fn new(name: FileName, entry: DirEntry) -> Self {
        DirectoryEntry { name, entry }
    }
}
