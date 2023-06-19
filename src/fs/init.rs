// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr};
use crate::error::SvsmError;
use crate::mm::ptguards::PerCPUPageMappingGuard;

use super::*;

extern crate alloc;
use alloc::slice;

const PACKIT_MAGIC: [u8; 4] = [0x50, 0x4b, 0x49, 0x54];

#[derive(Clone, Copy, Debug)]
struct PackItHeader {
    /// Header Magic (PKIT)
    magic: [u8; 4],
    /// Header Size
    header_size: u32,
}

impl PackItHeader {
    const fn new() -> Self {
        PackItHeader {
            magic: [0; 4],
            header_size: 8,
        }
    }

    fn load(buf: &[u8]) -> Result<Self, SvsmError> {
        if buf.len() < 8 {
            log::error!("Unexpected end of archive");
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        let mut hdr = PackItHeader::new();
        hdr.magic.copy_from_slice(&buf[0..4]);

        // array indexes are static so the try_into() never fails
        hdr.header_size = u32::from_le_bytes(buf[4..8].try_into().unwrap());

        if hdr.magic != PACKIT_MAGIC {
            log::error!("Unexpected header in FS archive");
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        Ok(hdr)
    }

    fn len(&self) -> usize {
        self.header_size as usize
    }
}

#[derive(Clone, Debug)]
struct FsArchive<'a> {
    _hdr: PackItHeader,
    data: &'a [u8],
    current: usize,
}

impl<'a> FsArchive<'a> {
    fn load(data: &'a [u8]) -> Result<Self, SvsmError> {
        let _hdr = PackItHeader::load(data)?;
        let current = _hdr.len();
        Ok(Self {
            _hdr,
            data,
            current,
        })
    }
}

impl<'a> core::iter::Iterator for FsArchive<'a> {
    type Item = Result<FsFile<'a>, SvsmError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.data.len() {
            return None;
        }

        let hdr = match FileHeader::load(&self.data[self.current..]) {
            Ok(hdr) => hdr,
            Err(e) => return Some(Err(e)),
        };

        let Some(start) = self.current.checked_add(hdr.header_size()) else {
            return Some(Err(SvsmError::FileSystem(FsError::inval())));
        };
        let Some(end) = start.checked_add(hdr.file_size()) else {
            return Some(Err(SvsmError::FileSystem(FsError::inval())));
        };
        let Some(data) = self.data.get(start..end) else {
            return Some(Err(SvsmError::FileSystem(FsError::inval())));
        };

        self.current += hdr.total_size();

        Some(Ok(FsFile { hdr, data }))
    }
}

struct FsFile<'a> {
    hdr: FileHeader<'a>,
    data: &'a [u8],
}

#[derive(Clone, Debug)]
struct FileHeader<'a> {
    name_len: u16,
    file_size: u64,
    name: &'a str,
}

impl<'a> FileHeader<'a> {
    fn load(buf: &'a [u8]) -> Result<Self, SvsmError> {
        if buf.len() < 12 {
            log::error!("Unexpected end of archive");
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        // array indexes are static so the try_into() never fails
        let hdr_type = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let name_len = u16::from_le_bytes(buf[2..4].try_into().unwrap());
        let file_size = u64::from_le_bytes(buf[4..12].try_into().unwrap());

        let header_len: usize = name_len as usize + 12;

        if buf.len() < header_len {
            log::error!("Unexpected end of archive");
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        let Ok(name) = core::str::from_utf8(&buf[12..header_len]) else {
            log::error!("Invalid filename in archive");
            return Err(SvsmError::FileSystem(FsError::inval()));
        };

        if hdr_type != 1 || name_len == 0 {
            log::error!("Invalid file header in archive");
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        Ok(Self {
            name_len,
            file_size,
            name,
        })
    }

    fn file_name(&self) -> &str {
        self.name
    }

    fn file_size(&self) -> usize {
        let size: usize = self.file_size.try_into().unwrap();
        size
    }

    fn header_size(&self) -> usize {
        let len: usize = self.name_len.into();
        12usize + len
    }

    fn total_size(&self) -> usize {
        self.file_size() + self.header_size()
    }
}

pub fn populate_ram_fs(kernel_fs_start: u64, kernel_fs_end: u64) -> Result<(), SvsmError> {
    assert!(kernel_fs_end >= kernel_fs_start);

    let pstart = PhysAddr::from(kernel_fs_start);
    let pend = PhysAddr::from(kernel_fs_end);
    let size = pend - pstart;

    if size == 0 {
        return Ok(());
    }

    log::info!("Unpacking FS archive...");

    let guard = PerCPUPageMappingGuard::create(pstart.page_align(), pend.page_align_up(), 0)?;
    let vstart = guard.virt_addr() + pstart.page_offset();

    let data: &[u8] = unsafe { slice::from_raw_parts(vstart.as_ptr(), size) };
    let archive = FsArchive::load(data)?;

    for file in archive {
        let file = file?;
        let handle = create_all(file.hdr.file_name())?;
        handle.truncate(0)?;
        let written = handle.write(file.data)?;
        if written != file.hdr.file_size() {
            log::error!("Incomplete data write to {}", file.hdr.file_name());
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        log::info!("  Unpacked {}", file.hdr.file_name());
    }

    log::info!("Unpacking done");

    Ok(())
}
