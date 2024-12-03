// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::{DirEntry, Directory, FileHandle, FileName};
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

#[allow(dead_code)]
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

    pub fn readdir(&self) -> Result<Option<(FileName, DirEntry)>, SvsmError> {
        let FsObjEntry::Directory(ref dh) = self.entry else {
            return Err(SvsmError::NotSupported);
        };

        let next = dh.next.fetch_add(1, Ordering::Relaxed);
        if let Some(&name) = dh.list.get(next) {
            let dirent = dh.dir.lookup_entry(name)?;
            Ok(Some((name, dirent)))
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
