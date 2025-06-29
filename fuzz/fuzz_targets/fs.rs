// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

#![no_main]

use arbitrary::Arbitrary;
use core::hint::black_box;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use svsm::fs::FileHandle;
use svsm::fs::{create, create_all, list_dir, mkdir, open_rw, unlink, TestFileSystemGuard};
use svsm::mm::alloc::TestRootMem;

const ROOT_MEM_SIZE: usize = 0x10000;
const MAX_READ_SIZE: usize = 4096 * 8;
const MAX_WRITE_SIZE: usize = 4096 * 8;
const WRITE_BYTE: u8 = 0x0;
const POISON_BYTE: u8 = 0xaf;

#[derive(Arbitrary, Debug)]
enum FsAction<'a> {
    Create(&'a str),
    CreateNamed(usize),
    CreateAll(&'a str),
    CreateAllNamed(usize),
    Open(&'a str),
    OpenNamed(usize),
    Close(usize),
    Unlink(&'a str),
    UnlinkNamed(usize),
    Mkdir(&'a str),
    MkdirNamed(usize),
    ListDir(&'a str),
    ListDirNamed(usize),
    Read(usize, usize),
    Write(usize, usize),
    Seek(usize, usize),
    Truncate(usize, usize),
}

fn get_idx<T>(v: &[T], idx: usize) -> Option<usize> {
    idx.checked_rem(v.len())
}

fn get_item<T>(v: &[T], idx: usize) -> Option<&T> {
    let idx = get_idx(v, idx)?;
    // SAFETY: we modulo the index to be within bounds
    Some(unsafe { v.get_unchecked(idx) })
}

/// A handle for a file that also holds its original name
#[derive(Debug)]
struct Handle<'a> {
    fd: FileHandle,
    name: &'a str,
}

impl<'a> Handle<'a> {
    fn new(fd: FileHandle, name: &'a str) -> Self {
        Self { fd, name }
    }
}

static MEM: OnceLock<TestRootMem<'_>> = OnceLock::new();

fuzz_target!(|actions: Vec<FsAction<'_>>| {
    // Initialize memory only once
    let _mem = MEM.get_or_init(|| TestRootMem::setup(ROOT_MEM_SIZE));

    let mut files = Vec::new();
    let mut aux_buf = vec![POISON_BYTE; MAX_READ_SIZE.max(MAX_WRITE_SIZE)];
    let _test_fs = TestFileSystemGuard::setup();

    for action in actions.iter() {
        match action {
            FsAction::Create(name) => {
                if let Ok(fh) = create(name) {
                    files.push(Handle::new(fh, name));
                }
            }
            FsAction::CreateNamed(idx) => {
                let Some(file) = get_item(&files, *idx) else {
                    continue;
                };
                if let Ok(fh) = create(file.name) {
                    files.push(Handle::new(fh, file.name));
                }
            }
            FsAction::CreateAll(name) => {
                if let Ok(fh) = create_all(name) {
                    files.push(Handle::new(fh, name));
                }
            }
            FsAction::CreateAllNamed(idx) => {
                let Some(file) = get_item(&files, *idx) else {
                    continue;
                };
                if let Ok(fh) = create_all(file.name) {
                    files.push(Handle::new(fh, file.name));
                }
            }
            FsAction::Open(name) => {
                if let Ok(fh) = open_rw(name) {
                    files.push(Handle::new(fh, name));
                }
            }
            FsAction::OpenNamed(idx) => {
                let Some(file) = get_item(&files, *idx) else {
                    continue;
                };
                if let Ok(fh) = open_rw(file.name) {
                    files.push(Handle::new(fh, file.name));
                }
            }
            FsAction::Close(idx) => {
                if let Some(idx) = get_idx(&files, *idx) {
                    let _ = files.swap_remove(idx);
                }
            }
            FsAction::Unlink(name) => {
                let _ = black_box(unlink(name));
            }
            FsAction::UnlinkNamed(idx) => {
                if let Some(file) = get_item(&files, *idx) {
                    let _ = black_box(unlink(file.name));
                }
            }
            FsAction::Mkdir(name) => {
                let _ = black_box(mkdir(name));
            }
            FsAction::MkdirNamed(idx) => {
                if let Some(file) = get_item(&files, *idx) {
                    let _ = black_box(mkdir(file.name));
                }
            }
            FsAction::ListDir(name) => {
                let _ = black_box(list_dir(name));
            }
            FsAction::ListDirNamed(idx) => {
                if let Some(file) = get_item(&files, *idx) {
                    let _ = black_box(list_dir(file.name));
                }
            }
            FsAction::Read(idx, len) => {
                let Some(file) = get_item(&files, *idx) else {
                    continue;
                };

                // Prepare the destination buffer
                let len = len % MAX_READ_SIZE;
                let buf = &mut aux_buf[..len];

                // Read some bytes
                let Ok(num) = file.fd.read(buf) else {
                    // No partial reads allowed if we got an error
                    assert!(aux_buf.iter().all(|c| *c == POISON_BYTE));
                    continue;
                };

                // Sanity check the bytes and reset the buffer
                assert!(num <= len);
                let (read, rest) = aux_buf.split_at_mut(num);
                assert!(read.iter().all(|c| *c == WRITE_BYTE));
                assert!(rest.iter().all(|c| *c == POISON_BYTE));
                read.fill(POISON_BYTE);
            }
            FsAction::Write(idx, len) => {
                let Some(file) = get_item(&files, *idx) else {
                    continue;
                };

                // Save the current position
                let start_pos = file.fd.position();

                // Prepare the source buffer
                let len = len % MAX_WRITE_SIZE;
                let (buf, rest) = aux_buf.split_at_mut(len);
                buf.fill(WRITE_BYTE);

                let Ok(num) = file.fd.write(buf) else {
                    assert!(buf.iter().all(|c| *c == WRITE_BYTE));
                    assert!(rest.iter().all(|c| *c == POISON_BYTE));
                    buf.fill(POISON_BYTE);
                    continue;
                };

                // Reset the buffer and the file position
                buf.fill(POISON_BYTE);
                file.fd.seek_abs(start_pos);

                // Read back the bytes and sanity check them
                assert!(num <= len);
                let (read, rest) = aux_buf.split_at_mut(num);
                let nread = file.fd.read(read).unwrap();
                assert_eq!(num, nread);
                assert!(read.iter().all(|c| *c == WRITE_BYTE));
                assert!(rest.iter().all(|c| *c == POISON_BYTE));

                // Reset the buffer
                read.fill(POISON_BYTE);
            }
            FsAction::Seek(idx, pos) => {
                if let Some(file) = get_item(&files, *idx) {
                    file.fd.seek_abs(*pos);
                }
            }
            FsAction::Truncate(idx, off) => {
                if let Some(file) = get_item(&files, *idx) {
                    let _ = black_box(file.fd.truncate(*off));
                }
            }
        }
    }
});
