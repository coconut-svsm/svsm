// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::{Buffer, DirEntry, Directory, FileHandle, FileName};
use crate::error::SvsmError;
use crate::syscall::Obj;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct DirectoryHandle {
    dir: Arc<dyn Directory>,
    list: Vec<FileName>,
    next: AtomicUsize,
}

impl DirectoryHandle {
    fn new(dir: &Arc<dyn Directory>) -> Self {
        DirectoryHandle {
            dir: dir.clone(),
            list: dir.list(),
            next: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
enum FsObjEntry {
    File(FileHandle),
    Directory(DirectoryHandle),
}

#[derive(Debug)]
pub struct FsObj {
    entry: FsObjEntry,
}

impl FsObj {
    pub fn new_dir(dir: &Arc<dyn Directory>) -> Self {
        FsObj {
            entry: FsObjEntry::Directory(DirectoryHandle::new(dir)),
        }
    }

    pub fn new_file(file_handle: FileHandle) -> Self {
        Self {
            entry: FsObjEntry::File(file_handle),
        }
    }

    pub fn read_buffer(&self, buffer: &mut dyn Buffer) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        fh.read_buffer(buffer)
    }

    pub fn write_buffer(&self, buffer: &dyn Buffer) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        fh.write_buffer(buffer)
    }

    pub fn seek_abs(&self, offset: usize) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        fh.seek_abs(offset);
        Ok(fh.position())
    }

    pub fn seek_rel(&self, offset: isize) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        fh.seek_rel(offset);
        Ok(fh.position())
    }

    pub fn seek_end(&self, offset: usize) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        fh.seek_end(offset);
        Ok(fh.position())
    }

    pub fn position(&self) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        Ok(fh.position())
    }

    pub fn file_size(&self) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        Ok(fh.size())
    }

    pub fn truncate(&self, length: usize) -> Result<usize, SvsmError> {
        let FsObjEntry::File(fh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        fh.truncate(length)
    }

    pub fn readdir(&self) -> Result<Option<(FileName, DirEntry)>, SvsmError> {
        let FsObjEntry::Directory(dh) = &self.entry else {
            return Err(SvsmError::NotSupported);
        };

        let next = dh.next.fetch_add(1, Ordering::Relaxed);
        if let Some(name) = dh.list.get(next) {
            let dirent = dh.dir.lookup_entry(name)?;
            Ok(Some((name.clone(), dirent)))
        } else {
            dh.next.fetch_sub(1, Ordering::Relaxed);
            Ok(None)
        }
    }
}

impl Obj for FsObj {
    fn as_fs(&self) -> Option<&FsObj> {
        Some(self)
    }
}
