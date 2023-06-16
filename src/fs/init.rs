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
use alloc::string::String;
use alloc::vec::Vec;

const PACKIT_MAGIC: [u8; 4] = [0x50, 0x4b, 0x49, 0x54];

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

struct FileHeader {
    name_len: u16,
    file_size: u64,
    name: String,
}

impl FileHeader {
    fn load(buf: &[u8]) -> Result<Self, SvsmError> {
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

        let Ok(name) = String::from_utf8(Vec::from(&buf[12..header_len])) else {
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
        self.name.as_str()
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
    let hdr = PackItHeader::load(data)?;

    let mut current = hdr.len();
    while current < size {
        let fh = FileHeader::load(&data[current..])?;

        let start = current
            .checked_add(fh.header_size())
            .ok_or(SvsmError::FileSystem(FsError::inval()))?;
        let end = start
            .checked_add(fh.file_size())
            .ok_or(SvsmError::FileSystem(FsError::inval()))?;

        let file = create_all(fh.file_name())?;
        let file_data = data
            .get(start..end)
            .ok_or(SvsmError::FileSystem(FsError::inval()))?;
        file.truncate(0)?;
        let written = file.write(file_data)?;
        if written != fh.file_size() {
            log::error!("Incomplete data write to {}", fh.file_name());
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        log::info!("  Unpacked {}", fh.file_name());
        current += fh.total_size();
    }

    log::info!("Unpacking done");

    Ok(())
}
