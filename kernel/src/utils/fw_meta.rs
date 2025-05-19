// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::types::PAGE_SIZE;
use uuid::Uuid;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use core::mem::{size_of, size_of_val};

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct RawMetaHeader {
    len: u16,
    uuid: [u8; size_of::<Uuid>()],
}

impl RawMetaHeader {
    pub const fn uuid(&self) -> Uuid {
        Uuid::from_bytes_le(self.uuid)
    }

    pub fn data_len(&self) -> Option<usize> {
        let full_len = self.len as usize;
        full_len.checked_sub(size_of::<Self>())
    }
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct RawMetaBuffer {
    pub data: [u8; PAGE_SIZE - size_of::<RawMetaHeader>() - 32],
    pub header: RawMetaHeader,
    _pad: [u8; 32],
}

impl RawMetaBuffer {
    pub fn pad_size(&self) -> usize {
        size_of_val(&self._pad)
    }
}

// Compile-time size checks
const _: () = assert!(size_of::<RawMetaBuffer>() == PAGE_SIZE);
const _: () = assert!(size_of::<RawMetaHeader>() == size_of::<u16>() + size_of::<Uuid>());

/// Find a table with the given UUID in the given memory slice, and return a
/// subslice into its data
pub fn find_table<'a>(uuid: &Uuid, mem: &'a [u8]) -> Option<&'a [u8]> {
    let mut idx = mem.len();

    while idx != 0 {
        let hdr_start = idx.checked_sub(size_of::<RawMetaHeader>())?;
        let hdr = RawMetaHeader::ref_from_bytes(&mem[hdr_start..idx]).unwrap();

        let data_len = hdr.data_len()?;
        idx = hdr_start.checked_sub(data_len)?;

        let raw_uuid = hdr.uuid;
        let curr_uuid = Uuid::from_bytes_le(raw_uuid);
        if *uuid == curr_uuid {
            return Some(&mem[idx..idx + data_len]);
        }
    }

    None
}
