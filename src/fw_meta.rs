// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, PhysAddr};
use crate::cpu::percpu::this_cpu_mut;
use crate::error::SvsmError;
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::SIZE_1G;
use crate::sev::ghcb::PageStateChangeOp;
use crate::sev::{pvalidate, rmp_adjust, PvalidateOp, RMPFlags};
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::{overlap, zero_mem_region};
use alloc::vec::Vec;

use core::cmp;
use core::fmt;
use core::mem::{align_of, size_of, size_of_val};
use core::str::FromStr;

#[derive(Copy, Clone, Debug)]
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

#[derive(Clone, Debug)]
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

fn from_hex(c: char) -> Result<u8, SvsmError> {
    match c.to_digit(16) {
        Some(d) => Ok(d as u8),
        None => Err(SvsmError::Firmware),
    }
}

#[derive(Copy, Clone, Debug)]
struct Uuid {
    data: [u8; 16],
}

impl Uuid {
    pub const fn new() -> Self {
        Uuid { data: [0; 16] }
    }
}

impl TryFrom<&[u8]> for Uuid {
    type Error = ();
    fn try_from(mem: &[u8]) -> Result<Self, Self::Error> {
        let arr: &[u8; 16] = mem.try_into().map_err(|_| ())?;
        Ok(Self::from(arr))
    }
}

impl From<&[u8; 16]> for Uuid {
    fn from(mem: &[u8; 16]) -> Self {
        Self {
            data: [
                mem[3], mem[2], mem[1], mem[0], mem[5], mem[4], mem[7], mem[6], mem[8], mem[9],
                mem[10], mem[11], mem[12], mem[13], mem[14], mem[15],
            ],
        }
    }
}

impl FromStr for Uuid {
    type Err = SvsmError;
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
        self.data.iter().zip(&other.data).all(|(a, b)| a == b)
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

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct SevMetaDataHeader {
    signature: [u8; 4],
    len: u32,
    version: u32,
    num_desc: u32,
}

#[derive(Clone, Copy, Debug)]
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

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct RawMetaHeader {
    len: u16,
    uuid: [u8; size_of::<Uuid>()],
}

impl RawMetaHeader {
    fn data_len(&self) -> Option<usize> {
        let full_len = self.len as usize;
        full_len.checked_sub(size_of::<Self>())
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct RawMetaBuffer {
    data: [u8; PAGE_SIZE - size_of::<RawMetaHeader>() - 32],
    header: RawMetaHeader,
    _pad: [u8; 32],
}

// Compile-time size checks
const _: () = assert!(size_of::<RawMetaBuffer>() == PAGE_SIZE);
const _: () = assert!(size_of::<RawMetaHeader>() == size_of::<u16>() + size_of::<Uuid>());

/// Find a table with the given UUID in the given memory slice, and return a
/// subslice into its data
fn find_table<'a>(uuid: &Uuid, mem: &'a [u8]) -> Option<&'a [u8]> {
    let mut idx = mem.len();

    while idx != 0 {
        let hdr_start = idx.checked_sub(size_of::<RawMetaHeader>())?;
        let hdr_start_ptr = mem.get(hdr_start..idx)?.as_ptr().cast::<RawMetaHeader>();
        if hdr_start_ptr.align_offset(align_of::<RawMetaHeader>()) != 0 {
            log::error!("Misaligned firmware metadata table");
            return None;
        }

        // Safety: we have checked the pointer is within bounds and aligned
        let hdr = unsafe { hdr_start_ptr.read() };

        let data_len = hdr.data_len()?;
        idx = hdr_start.checked_sub(data_len)?;

        let raw_uuid = hdr.uuid;
        let curr_uuid = Uuid::from(&raw_uuid);
        if *uuid == curr_uuid {
            return Some(&mem[idx..idx + data_len]);
        }
    }

    None
}

pub fn parse_fw_meta_data() -> Result<SevFWMetaData, SvsmError> {
    let mut meta_data = SevFWMetaData::new();
    // Map meta-data location, it starts at 32 bytes below 4GiB
    let pstart = PhysAddr::from((4 * SIZE_1G) - PAGE_SIZE);
    let guard = PerCPUPageMappingGuard::create_4k(pstart)?;
    let vstart = guard.virt_addr();

    // Safety: RawMetaBuffer has a size of one page and it has no invalid
    // representations.
    let raw_meta = unsafe { &*vstart.as_ptr::<RawMetaBuffer>() };

    // Check the UUID
    let raw_uuid = raw_meta.header.uuid;
    let uuid = Uuid::from(&raw_uuid);
    let meta_uuid = Uuid::from_str(OVMF_TABLE_FOOTER_GUID)?;
    if uuid != meta_uuid {
        return Err(SvsmError::Firmware);
    }

    // Get the tables and their length
    let data_len = raw_meta.header.data_len().ok_or(SvsmError::Firmware)?;
    let data_start = size_of_val(&raw_meta.data)
        .checked_sub(data_len)
        .ok_or(SvsmError::Firmware)?;
    let raw_data = raw_meta.data.get(data_start..).ok_or(SvsmError::Firmware)?;

    // First check if this is the SVSM itself instead of OVMF
    let svsm_info_uuid = Uuid::from_str(SVSM_INFO_GUID)?;
    if find_table(&svsm_info_uuid, raw_data).is_some() {
        return Err(SvsmError::Firmware);
    }

    // Search SEV_INFO_BLOCK_GUID
    let sev_info_uuid = Uuid::from_str(SEV_INFO_BLOCK_GUID)?;
    if let Some(tbl) = find_table(&sev_info_uuid, raw_data) {
        let bytes: [u8; 4] = tbl.try_into().map_err(|_| SvsmError::Firmware)?;
        let reset_ip = u32::from_le_bytes(bytes) as usize;
        meta_data.reset_ip = Some(PhysAddr::from(reset_ip));
    }

    // Search and parse SEV metadata
    parse_sev_meta(&mut meta_data, raw_meta, raw_data)?;
    Ok(meta_data)
}

fn parse_sev_meta(
    meta: &mut SevFWMetaData,
    raw_meta: &RawMetaBuffer,
    raw_data: &[u8],
) -> Result<(), SvsmError> {
    // Find SEV metadata table
    let sev_meta_uuid = Uuid::from_str(OVMF_SEV_META_DATA_GUID)?;
    let Some(tbl) = find_table(&sev_meta_uuid, raw_data) else {
        log::warn!("Could not find SEV metadata in firmware");
        return Ok(());
    };

    // Find the location of the metadata header. We need to adjust the offset
    // since it is computed by taking into account the trailing header and
    // padding, and it is computed backwards.
    let bytes: [u8; 4] = tbl.try_into().map_err(|_| SvsmError::Firmware)?;
    let sev_meta_offset = (u32::from_le_bytes(bytes) as usize)
        .checked_sub(size_of_val(&raw_meta.header) + size_of_val(&raw_meta._pad))
        .ok_or(SvsmError::Firmware)?;
    // Now compute the start and end of the SEV metadata header
    let sev_meta_start = size_of_val(&raw_meta.data)
        .checked_sub(sev_meta_offset)
        .ok_or(SvsmError::Firmware)?;
    let sev_meta_end = sev_meta_start + size_of::<SevMetaDataHeader>();
    // Bounds check the header and get a pointer to it
    let sev_meta_hdr_ptr = raw_meta
        .data
        .get(sev_meta_start..sev_meta_end)
        .ok_or(SvsmError::Firmware)?
        .as_ptr()
        .cast::<SevMetaDataHeader>();

    // Check that the header pointer is aligned. This also guarantees that
    // descriptors down the line will be aligned. If the pointer was not
    // aligned we would need to use ptr::read_unaligned(), so simply check
    // beforehand and use ptr::read(), as there's no reason for the metadata
    // to be misaligned.
    if sev_meta_hdr_ptr.align_offset(align_of::<SevMetaDataHeader>()) != 0 {
        log::error!("Misaligned SEV metadata header");
        return Err(SvsmError::Firmware);
    }
    // Safety: we have checked the pointer is within bounds and aligned.
    let sev_meta_hdr = unsafe { sev_meta_hdr_ptr.read() };

    // Now find the descriptors
    let num_desc = sev_meta_hdr.num_desc as usize;
    let sev_descs_start = sev_meta_end;
    let sev_descs_len = num_desc
        .checked_mul(size_of::<SevMetaDataDesc>())
        .ok_or(SvsmError::Firmware)?;
    let sev_descs_end = sev_descs_start
        .checked_add(sev_descs_len)
        .ok_or(SvsmError::Firmware)?;

    // We have a variable number of descriptors following the header.
    // Unfortunately flexible array members in Rust are not fully supported,
    // so we cannot avoid using raw pointers.
    let sev_descs_ptr = raw_meta
        .data
        .get(sev_descs_start..sev_descs_end)
        .ok_or(SvsmError::Firmware)?
        .as_ptr()
        .cast::<SevMetaDataDesc>();

    for i in 0..num_desc {
        // Safety: We have checked that the descriptors are within bounds of
        // the metadata memory. Since the descriptors follow the header, and
        // the header is properly aligned, the descriptors must be so as
        // well.
        let desc = unsafe { sev_descs_ptr.add(i).read() };
        let t = desc.t;
        let base = PhysAddr::from(desc.base as usize);
        let len = desc.len as usize;

        match t {
            SEV_META_DESC_TYPE_MEM => meta.add_valid_mem(base, len),
            SEV_META_DESC_TYPE_SECRETS => {
                if len != PAGE_SIZE {
                    return Err(SvsmError::Firmware);
                }
                meta.secrets_page = Some(base);
            }
            SEV_META_DESC_TYPE_CPUID => {
                if len != PAGE_SIZE {
                    return Err(SvsmError::Firmware);
                }
                meta.cpuid_page = Some(base);
            }
            SEV_META_DESC_TYPE_CAA => {
                if len != PAGE_SIZE {
                    return Err(SvsmError::Firmware);
                }
                meta.caa_page = Some(base);
            }
            _ => log::info!("Unknown metadata item type: {}", t),
        }
    }

    Ok(())
}

fn validate_fw_mem_region(region: SevPreValidMem) -> Result<(), SvsmError> {
    let pstart = region.base;
    let pend = region.end();

    log::info!("Validating {:#018x}-{:#018x}", pstart, pend);

    this_cpu_mut()
        .ghcb()
        .page_state_change(
            pstart,
            pend,
            PageSize::Regular,
            PageStateChangeOp::PscPrivate,
        )
        .expect("GHCB PSC call failed to validate firmware memory");

    for paddr in (pstart.bits()..pend.bits())
        .step_by(PAGE_SIZE)
        .map(PhysAddr::from)
    {
        let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
        let vaddr = guard.virt_addr();

        pvalidate(vaddr, PageSize::Regular, PvalidateOp::Valid)?;

        // Make page accessible to guest VMPL
        rmp_adjust(
            vaddr,
            RMPFlags::GUEST_VMPL | RMPFlags::RWX,
            PageSize::Regular,
        )?;

        zero_mem_region(vaddr, vaddr + PAGE_SIZE);
    }

    Ok(())
}

fn validate_fw_memory_vec(regions: Vec<SevPreValidMem>) -> Result<(), SvsmError> {
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

pub fn validate_fw_memory(fw_meta: &SevFWMetaData) -> Result<(), SvsmError> {
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
