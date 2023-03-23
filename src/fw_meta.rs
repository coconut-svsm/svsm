// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::percpu::this_cpu_mut;
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::SIZE_1G;
use crate::sev::ghcb::PageStateChangeOp;
use crate::sev::{pvalidate, rmp_adjust, RMPFlags};
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use crate::utils::{overlap, zero_mem_region};
use alloc::vec::Vec;

use core::cmp;
use core::fmt;
use core::mem;
use core::str::FromStr;

#[derive(Copy, Clone)]
pub struct SevPreValidMem {
    base: PhysAddr,
    length: usize,
}

impl SevPreValidMem {
    fn new(base: PhysAddr, length: usize) -> Self {
        Self { base, length }
    }

    fn new_4k(base: PhysAddr) -> Self {
        Self::new(base, PAGE_SIZE)
    }

    #[inline]
    fn end(&self) -> PhysAddr {
        self.base + self.length
    }

    fn overlap(&self, other: &Self) -> bool {
        overlap(self.base, self.end(), other.base, other.end())
    }

    fn merge(self, other: Self) -> Self {
        let base = cmp::min(self.base, other.base);
        let length = cmp::max(self.end(), other.end()) - base;
        Self::new(base, length)
    }
}

pub struct SevFWMetaData {
    pub reset_ip: Option<PhysAddr>,
    pub cpuid_page: Option<PhysAddr>,
    pub secrets_page: Option<PhysAddr>,
    pub caa_page: Option<PhysAddr>,
    pub valid_mem: Vec<SevPreValidMem>,
}

impl SevFWMetaData {
    pub const fn new() -> Self {
        SevFWMetaData {
            reset_ip: None,
            cpuid_page: None,
            secrets_page: None,
            caa_page: None,
            valid_mem: Vec::new(),
        }
    }

    pub fn add_valid_mem(&mut self, base: PhysAddr, len: usize) {
        self.valid_mem.push(SevPreValidMem::new(base, len));
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
}

impl FromStr for Uuid {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut uuid = Uuid::new();
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
                uuid.data[i] = buf;
            }

            index += 1;
        }

        Ok(uuid)
    }
}

impl PartialEq for Uuid {
    fn eq(&self, other: &Self) -> bool {
        for (a, b) in self.data.iter().zip(&other.data) {
            if a != b {
                return false;
            }
        }
        return true;
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
const SEV_META_DESC_TYPE_CAA: u32 = 4;

pub fn parse_fw_meta_data() -> Result<SevFWMetaData, ()> {
    let pstart: PhysAddr = (4 * SIZE_1G) - PAGE_SIZE;
    let mut meta_data = SevFWMetaData::new();

    // Map meta-data location, it starts at 32 bytes below 4GiB
    let guard = PerCPUPageMappingGuard::create(pstart, 0, false).map_err(|_e| ())?;
    let vstart = guard.virt_addr();
    let vend: VirtAddr = vstart + PAGE_SIZE;

    let mut curr = vend - 32;

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
            let offset = off_ptr.read_unaligned() as usize;

            let meta_ptr = (vend - offset) as *const SevMetaDataHeader;
            //let len = meta_ptr.read().len;
            let num_descs = meta_ptr.read().num_desc as isize;
            let desc_ptr = meta_ptr.offset(1).cast::<SevMetaDataDesc>();

            for i in 0..num_descs {
                let desc = desc_ptr.offset(i).read();
                let t = desc.t;
                let base = desc.base as PhysAddr;
                let len = desc.len as usize;
                match t {
                    SEV_META_DESC_TYPE_MEM => meta_data.add_valid_mem(base, len),
                    SEV_META_DESC_TYPE_SECRETS => {
                        if len != PAGE_SIZE {
                            return Err(());
                        }
                        meta_data.secrets_page = Some(base);
                    }
                    SEV_META_DESC_TYPE_CPUID => {
                        if len != PAGE_SIZE {
                            return Err(());
                        }
                        meta_data.cpuid_page = Some(base);
                    }
                    SEV_META_DESC_TYPE_CAA => {
                        if len != PAGE_SIZE {
                            return Err(());
                        }
                        meta_data.caa_page = Some(base);
                    }
                    _ => log::info!("Unknown metadata item type: {}", t),
                }
            }
        }
    }

    Ok(meta_data)
}

fn validate_fw_mem_region(region: SevPreValidMem) -> Result<(), ()> {
    let pstart: PhysAddr = region.base;
    let pend: PhysAddr = region.end();

    log::info!("Validating {:#018x}-{:#018x}", pstart, pend);

    this_cpu_mut()
        .ghcb()
        .page_state_change(pstart, pend, false, PageStateChangeOp::PscPrivate)
        .expect("GHCB PSC call failed to validate firmware memory");

    for paddr in (pstart..pend).step_by(PAGE_SIZE) {
        let guard = PerCPUPageMappingGuard::create(paddr, 0, false).map_err(|_e| ())?;
        let vaddr = guard.virt_addr();

        if pvalidate(vaddr, false, true).is_err() {
            return Err(());
        }

        // Make page accessible to VMPL1
        if rmp_adjust(vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, false).is_err() {
            return Err(());
        }

        zero_mem_region(vaddr, vaddr + PAGE_SIZE);
    }

    Ok(())
}

fn validate_fw_memory_vec(regions: Vec<SevPreValidMem>) -> Result<(), ()> {
    if regions.is_empty() {
        return Ok(());
    }

    let mut next_vec: Vec<SevPreValidMem> = Vec::new();
    let mut region = regions[0];

    for next in regions.into_iter().skip(1) {
        if region.overlap(&next) {
            region = region.merge(next);
        } else {
            next_vec.push(next);
        }
    }

    validate_fw_mem_region(region)?;
    validate_fw_memory_vec(next_vec)
}

pub fn validate_fw_memory(fw_meta: &SevFWMetaData) -> Result<(), ()> {
    // Initalize vector with regions from the FW
    let mut regions = fw_meta.valid_mem.clone();

    // Add region for CPUID page if present
    if let Some(cpuid_paddr) = fw_meta.cpuid_page {
        regions.push(SevPreValidMem::new_4k(cpuid_paddr));
    }

    // Add region for Secrets page if present
    if let Some(secrets_paddr) = fw_meta.secrets_page {
        regions.push(SevPreValidMem::new_4k(secrets_paddr));
    }

    // Add region for CAA page if present
    if let Some(caa_paddr) = fw_meta.caa_page {
        regions.push(SevPreValidMem::new_4k(caa_paddr));
    }

    // Sort regions by base address
    regions.sort_unstable_by(|a, b| a.base.cmp(&b.base));

    validate_fw_memory_vec(regions)
}

pub fn print_fw_meta(fw_meta: &SevFWMetaData) {
    log::info!("FW Meta Data");

    match fw_meta.reset_ip {
        Some(ip) => log::info!("  Reset RIP    : {:#010x}", ip),
        None => log::info!("  Reset RIP    : None"),
    };

    match fw_meta.cpuid_page {
        Some(addr) => log::info!("  CPUID Page   : {:#010x}", addr),
        None => log::info!("  CPUID Page   : None"),
    };

    match fw_meta.secrets_page {
        Some(addr) => log::info!("  Secrets Page : {:#010x}", addr),
        None => log::info!("  Secrets Page : None"),
    };

    match fw_meta.caa_page {
        Some(addr) => log::info!("  CAA Page     : {:#010x}", addr),
        None => log::info!("  CAA Page     : None"),
    };

    for region in &fw_meta.valid_mem {
        log::info!(
            "  Pre-Validated Region {:#018x}-{:#018x}",
            region.base,
            region.end()
        );
    }
}
