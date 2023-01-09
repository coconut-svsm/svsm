// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

extern crate alloc;

use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use alloc::vec::Vec;
use crate::mm::pagetable::PTMappingGuard;

use core::fmt;
use core::mem;

#[allow(dead_code)]
pub struct SevPreValidMem {
    base: PhysAddr,
    length: usize,
}

pub struct SevFWMetaData {
    pub reset_ip: Option<PhysAddr>,
    pub cpuid_page: Option<PhysAddr>,
    pub secrets_page: Option<PhysAddr>,
    pub valid_mem: Vec<SevPreValidMem>,
}

impl SevFWMetaData {
    pub const fn new() -> Self {
        SevFWMetaData {
            reset_ip: None,
            cpuid_page: None,
            secrets_page: None,
            valid_mem: Vec::new(),
        }
    }

    pub fn add_valid_mem(&mut self, base: PhysAddr, len: usize) {
        self.valid_mem.push(SevPreValidMem {
            base: base,
            length: len,
        });
    }
}

struct Uuid {
    data: [u8; 16],
}

fn from_hex(c: char) -> Result<u8, ()> {
    match c.to_digit(16) {
        Some(d) => Ok(d as u8),
        None => Err(()),
    }
}

impl Uuid {
    pub const fn new() -> Self {
        Uuid { data: [0; 16] }
    }

    pub fn parse(&mut self, s: &str) -> Result<(), ()> {
        let mut buf: u8 = 0;

        let mut index = 0;
        for c in s.chars() {
            if !c.is_ascii_hexdigit() {
                continue;
            }

            if (index % 2) == 0 {
                buf = from_hex(c)? << 4;
            } else {
                buf |= from_hex(c)?;
                let i = index / 2;
                if i >= 16 {
                    break;
                }
                self.data[i] = buf;
            }

            index += 1;
        }
        Ok(())
    }

    pub fn from_str(s: &str) -> Result<Self, ()> {
        let mut uuid = Uuid::new();
        uuid.parse(s)?;

        Ok(uuid)
    }

    pub unsafe fn from_mem(ptr: *const u8) -> Self {
        Uuid {
            data: [
                ptr.offset(3).read(),
                ptr.offset(2).read(),
                ptr.offset(1).read(),
                ptr.offset(0).read(),
                ptr.offset(5).read(),
                ptr.offset(4).read(),
                ptr.offset(7).read(),
                ptr.offset(6).read(),
                ptr.offset(8).read(),
                ptr.offset(9).read(),
                ptr.offset(10).read(),
                ptr.offset(11).read(),
                ptr.offset(12).read(),
                ptr.offset(13).read(),
                ptr.offset(14).read(),
                ptr.offset(15).read(),
            ],
        }
    }

    fn equal(&self, other: &Uuid) -> bool {
        for i in 0..16 {
            if self.data[i] != other.data[i] {
                return false;
            }
        }
        return true;
    }
}

impl PartialEq for Uuid {
    fn eq(&self, other: &Uuid) -> bool {
        self.equal(other)
    }

    fn ne(&self, other: &Uuid) -> bool {
        !self.equal(other)
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..16 {
            write!(f, "{:02x}", self.data[i])?;
            if i == 3 || i == 5 || i == 7 || i == 9 {
                write!(f, "-")?;
            }
        }
        Ok(())
    }
}

const OVMF_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const OVMF_SEV_META_DATA_GUID: &str = "dc886566-984a-4798-a75e-5585a7bf67cc";
const SEV_INFO_BLOCK_GUID: &str = "00f771de-1a7e-4fcb-890e-68c77e2fb44e";
const SVSM_INFO_GUID: &str = "a789a612-0597-4c4b-a49f-cbb1fe9d1ddd";

unsafe fn find_table(uuid: &Uuid, start: VirtAddr, len: VirtAddr) -> Result<(VirtAddr, usize), ()> {
    let mut curr = start;
    let end = start - len;

    while curr >= end {
        curr -= mem::size_of::<Uuid>();

        let ptr = curr as *const u8;
        let curr_uuid = Uuid::from_mem(ptr);

        curr -= mem::size_of::<u16>();
        if curr < end {
            break;
        }

        let len_ptr = curr as *const u16;
        let orig_len = len_ptr.read() as usize;

        if len < mem::size_of::<Uuid>() + mem::size_of::<u16>() {
            break;
        }
        let len = orig_len - (mem::size_of::<Uuid>() + mem::size_of::<u16>());

        curr -= len;

        if *uuid == curr_uuid {
            return Ok((curr, len));
        }
    }

    Err(())
}

#[repr(C, packed)]
struct SevMetaDataHeader {
    signature: [u8; 4],
    len: u32,
    version: u32,
    num_desc: u32,
}

#[repr(C, packed)]
struct SevMetaDataDesc {
    base: u32,
    len: u32,
    t: u32,
}

const SEV_META_DESC_TYPE_MEM: u32 = 1;
const SEV_META_DESC_TYPE_SECRETS: u32 = 2;
const SEV_META_DESC_TYPE_CPUID: u32 = 3;

pub fn parse_fw_meta_data() -> Result<SevFWMetaData, ()> {
    let end: VirtAddr = 0x1_0000_0000usize;
    let start = end - PAGE_SIZE;
    let phys: PhysAddr = start as PhysAddr;

    let mut meta_data = SevFWMetaData::new();

    // Map meta-data location, it starts at 32 bytes below 4GiB
    let mapping_guard = PTMappingGuard::create(start, end, phys);
    mapping_guard.check_mapping()?;

    let mut curr = end - 32;

    let meta_uuid = Uuid::from_str(OVMF_TABLE_FOOTER_GUID)?;

    curr -= mem::size_of::<Uuid>();
    let ptr = curr as *const u8;

    unsafe {
        let uuid = Uuid::from_mem(ptr);

        if uuid != meta_uuid {
            return Err(());
        }

        curr -= mem::size_of::<u16>();
        let ptr = curr as *const u16;

        let full_len = ptr.read() as usize;
        let len = full_len - mem::size_of::<u16>() + mem::size_of::<Uuid>();

        // First check if this is the SVSM itself instead of OVMF
        let svsm_info_uuid = Uuid::from_str(SVSM_INFO_GUID).unwrap();
        if let Ok(_v) = find_table(&svsm_info_uuid, curr, len) {
            return Err(());
        }

        // Search SEV_INFO_BLOCK_GUID
        let sev_info_uuid = Uuid::from_str(SEV_INFO_BLOCK_GUID).unwrap();
        let ret = find_table(&sev_info_uuid, curr, len);
        if let Ok(tbl) = ret {
            let (base, len) = tbl;
            if len != mem::size_of::<u32>() {
                return Err(());
            }
            let info_ptr = base as *const u32;
            meta_data.reset_ip = Some(info_ptr.read() as PhysAddr);
        }

        // Search and parse Meta Data
        let sev_meta_uuid = Uuid::from_str(OVMF_SEV_META_DATA_GUID).unwrap();
        let ret = find_table(&sev_meta_uuid, curr, len);
        if let Ok(tbl) = ret {
            let (base, _len) = tbl;
            let off_ptr = base as *const u32;
            let offset = off_ptr.read() as usize;

            let meta_ptr = (end - offset) as *const SevMetaDataHeader;
            //let len = meta_ptr.read().len;
            let num_descs = meta_ptr.read().num_desc as isize;
            let desc_ptr = meta_ptr.offset(1).cast::<SevMetaDataDesc>();

            for i in 0..num_descs {
                let desc = desc_ptr.offset(i).read();
                let t = desc.t;
                let base = desc.base as PhysAddr;
                let len = desc.len as usize;
                if t == SEV_META_DESC_TYPE_MEM {
                    meta_data.add_valid_mem(base, len);
                } else if t == SEV_META_DESC_TYPE_SECRETS {
                    if len != PAGE_SIZE {
                        return Err(());
                    }
                    meta_data.secrets_page = Some(base);
                } else if t == SEV_META_DESC_TYPE_CPUID {
                    if len != PAGE_SIZE {
                        return Err(());
                    }
                    meta_data.cpuid_page = Some(base);
                }
            }
        }
    }

    Ok(meta_data)
}
