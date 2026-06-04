// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;

use bootdefs::boot_params::GuestFwInfoBlock;
use bootdefs::boot_params::GuestFwMemInfo;
use bootdefs::boot_params::InitialGuestContext;
use bootdefs::firmware::*;
use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};
use uuid::Uuid;
use zerocopy::{FromBytes, KnownLayout};

use crate::GpaMap;
use crate::firmware::Firmware;
use crate::igvm_builder::{NATIVE_COMPATIBILITY_MASK, SNP_COMPATIBILITY_MASK};

// Offset from the end of the file where the OVMF table footer GUID should be.
const FOOTER_OFFSET: usize = 32;

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct GuidBlockFooter {
    len: u16,
    guid: [u8; 16],
}

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct GuidBlockMetadata {
    offset_from_end: u32,
}

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct GuidBlockResetVector {
    vector_address: u32,
    compatibility_mask: u32,
}

trait Metadata {
    fn signature(&self) -> [u8; 4];

    fn parse<'a>(
        &mut self,
        data: &'a [u8],
        fw_info: &mut GuestFwInfoBlock,
    ) -> Result<&'a [u8], Box<dyn Error>>;
}

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct SevMetadataEntry {
    base: u32,
    len: u32,
    metadata_type: u32,
}

struct SevMetadata {}

impl Metadata for SevMetadata {
    fn signature(&self) -> [u8; 4] {
        [b'A', b'S', b'E', b'V']
    }

    fn parse<'a>(
        &mut self,
        data: &'a [u8],
        fw_info: &mut GuestFwInfoBlock,
    ) -> Result<&'a [u8], Box<dyn Error>> {
        let (entry, remainder) = SevMetadataEntry::read_from_prefix(data)
            .map_err(|e| format!("Cannot parse SEV metadata entry: {e}"))?;
        match entry.metadata_type {
            SEV_META_DESC_TYPE_MEM | SEV_META_DESC_TYPE_KERNEL_HASHES => {
                add_preval_region(fw_info, entry.base, entry.len)?
            }
            SEV_META_DESC_TYPE_SECRETS => fw_info.secrets_page = entry.base,
            SEV_META_DESC_TYPE_CPUID => fw_info.cpuid_page = entry.base,
            SEV_META_DESC_TYPE_CAA => fw_info.caa_page = entry.base,
            _ => {}
        }
        Ok(remainder)
    }
}

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct TdxMetadataEntry {
    _raw_offset: u32,
    _raw_size: u32,
    _mem_address: u64,
    _mem_size: u64,
    _section_type: u32,
    _attributes: u32,
}

struct TdxMetadata {}

impl Metadata for TdxMetadata {
    fn signature(&self) -> [u8; 4] {
        [b'T', b'D', b'V', b'F']
    }

    fn parse<'a>(
        &mut self,
        data: &'a [u8],
        _fw_info: &mut GuestFwInfoBlock,
    ) -> Result<&'a [u8], Box<dyn Error>> {
        let (_entry, remainder) = TdxMetadataEntry::read_from_prefix(data)
            .map_err(|e| format!("Cannot parse TDX metadata entry: {e}"))?;
        // Do nothing other than making sure parsing succeeds for now
        Ok(remainder)
    }
}

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct IgvmMetadataEntry {
    start: u32,
    len: u32,
    metadata_type: u32,
}

struct IgvmMetadata {
    param_area: Option<(u32, u32)>, // (start, size)
}

impl IgvmMetadata {
    fn new() -> Self {
        IgvmMetadata { param_area: None }
    }
}

impl Metadata for IgvmMetadata {
    fn signature(&self) -> [u8; 4] {
        [b'I', b'G', b'V', b'M']
    }

    fn parse<'a>(
        &mut self,
        data: &'a [u8],
        fw_info: &mut GuestFwInfoBlock,
    ) -> Result<&'a [u8], Box<dyn Error>> {
        let (entry, remainder) = IgvmMetadataEntry::read_from_prefix(data)
            .map_err(|e| format!("Cannot parse IGVM metadata entry: {e}"))?;
        match entry.metadata_type {
            IGVM_META_DESC_TYPE_PARAM_AREA => {
                if self.param_area.is_some() {
                    return Err("Found multiple IGVM param areas".into());
                }
                add_preval_region(fw_info, entry.start, entry.len)?;
                self.param_area = Some((entry.start, entry.len));
            }
            IGVM_META_DESC_TYPE_MEMORY_MAP => {
                // IGVM_META_DESC_TYPE_PARAM_AREA must precede it.
                let param_area = self.param_area.ok_or("IGVM param area not found")?;
                // Capture the memory map in the firmware information.
                fw_info.memory_map_address = param_area
                    .0
                    .checked_add(entry.start)
                    .ok_or("IGVM memory map area exceeds 32 bits")?;
                fw_info.memory_map_size = entry.len;

                if !region_contains(
                    param_area,
                    (fw_info.memory_map_address, fw_info.memory_map_size),
                ) {
                    return Err("IGVM memory map not included in IGVM param area".into());
                }
                fw_info.memory_map_prevalidated = 1;
            }
            IGVM_META_DESC_TYPE_HOB_AREA => add_preval_region(fw_info, entry.start, entry.len)?,
            _ => {}
        }
        Ok(remainder)
    }
}

#[derive(FromBytes, KnownLayout)]
#[repr(C)]
struct MetadataDesc {
    sig: [u8; 4],
    _len: u32,
    _version: u32,
    num_desc: u32,
}

fn region_overlaps(this: (u32, u32), that: (u32, u32)) -> bool {
    let (this_start, this_end) = (this.0 as u64, this.0 as u64 + this.1 as u64);
    let (that_start, that_end) = (that.0 as u64, that.0 as u64 + that.1 as u64);
    this_start < that_end && this_end > that_start
}

fn region_contains(this: (u32, u32), that: (u32, u32)) -> bool {
    let (this_start, this_end) = (this.0 as u64, this.0 as u64 + this.1 as u64);
    let (that_start, that_end) = (that.0 as u64, that.0 as u64 + that.1 as u64);
    this_start <= that_start && that_end <= this_end
}

fn region_contiguous(this: (u32, u32), that: (u32, u32)) -> bool {
    let (this_start, this_end) = (this.0 as u64, this.0 as u64 + this.1 as u64);
    let (that_start, that_end) = (that.0 as u64, that.0 as u64 + that.1 as u64);
    this_start <= that_end && this_end >= that_start
}

fn region_merge(this: (u32, u32), that: (u32, u32)) -> Option<(u32, u32)> {
    let (this_start, this_end) = (this.0 as u64, this.0 as u64 + this.1 as u64);
    let (that_start, that_end) = (that.0 as u64, that.0 as u64 + that.1 as u64);
    let start = this_start.min(that_start);
    let end = this_end.max(that_end);
    let len = u32::try_from(end - start).ok()?;
    Some((start as u32, len))
}

fn add_preval_region(
    fw_info: &mut GuestFwInfoBlock,
    base: u32,
    size: u32,
) -> Result<(), Box<dyn Error>> {
    let preval_count = fw_info.prevalidated_count as usize;
    let preval_regions = &mut fw_info.prevalidated[..preval_count];
    if let Some(preval) = preval_regions
        .iter_mut()
        .find(|preval| region_contiguous((preval.base, preval.size), (base, size)))
    {
        let (pstart, psize) = (preval.base, preval.size);
        let merged = region_merge((pstart, psize), (base, size)).ok_or(format!(
            "OVMF pre-validated area [{:#x}-{:#x}] merge overflow",
            base,
            base as u64 + size as u64
        ))?;
        println!(
            "Region [{:#x}-{:#x}] merged with existing pre-validated area [{:#x}-{:#x}] -> [{:#x}-{:#x}]",
            base,
            base as u64 + size as u64,
            pstart,
            pstart as u64 + psize as u64,
            merged.0,
            merged.0 as u64 + merged.1 as u64
        );
        *preval = GuestFwMemInfo {
            base: merged.0,
            size: merged.1,
        };
    } else {
        if preval_count >= fw_info.prevalidated.len() {
            return Err("OVMF metadata defines too many memory regions".into());
        }
        fw_info.prevalidated[preval_count] = GuestFwMemInfo { base, size };
        fw_info.prevalidated_count += 1;
    }
    Ok(())
}

// (table uuid, table body, remaining data)
type TableInfo<'a> = (Uuid, &'a [u8], &'a [u8]);

fn read_table(data: &[u8]) -> Result<TableInfo<'_>, Box<dyn Error>> {
    let (_, footer) = GuidBlockFooter::read_from_suffix(data)
        .map_err(|e| format!("Invalid metadata table in OVMF firmware: {e}"))?;
    let table_size = footer.len as usize;
    if table_size < size_of::<GuidBlockFooter>() || table_size > data.len() {
        return Err("Invalid metadata table in OVMF firmware: invalid table size".into());
    }
    Ok((
        Uuid::from_bytes_le(footer.guid),
        &data[(data.len() - table_size)..(data.len() - size_of::<GuidBlockFooter>())],
        &data[..data.len() - table_size],
    ))
}

fn parse_metadata(
    data: &[u8],
    fw_img: &[u8],
    metadata: &mut dyn Metadata,
    fw_info: &mut GuestFwInfoBlock,
) -> Result<(), Box<dyn Error>> {
    let offset_from_end = GuidBlockMetadata::read_from_bytes(data)
        .map_err(|e| format!("Cannot parse OVMF metadata descriptor: {e}"))?
        .offset_from_end as usize;
    let offset = fw_img
        .len()
        .checked_sub(offset_from_end)
        .ok_or("Cannot parse OVMF metadata descriptor: invalid offset")?;
    let (desc, mut buf) = MetadataDesc::read_from_prefix(&fw_img[offset..])
        .map_err(|e| format!("Cannot parse OVMF metadata descriptor: {e}"))?;

    if desc.sig != metadata.signature() {
        return Err(format!("OVMF metadata signature mismatch: {:?}", desc.sig).into());
    }
    for _ in 0..desc.num_desc as usize {
        buf = metadata.parse(buf, fw_info)?;
    }
    Ok(())
}

fn parse_sev_info_block(
    _data: &[u8],
    _fw_info: &mut GuestFwInfoBlock,
) -> Result<(), Box<dyn Error>> {
    // Not currently used
    //fw_info.reset_addr = read_u32(data)?;
    Ok(())
}

fn parse_reset_vector(data: &[u8], fw_info: &mut GuestFwInfoBlock) -> Result<u32, Box<dyn Error>> {
    let rv_info = GuidBlockResetVector::read_from_bytes(data)
        .map_err(|e| format!("Cannot parse OVMF reset vector: {e}"))?;
    let vector_off = fw_info
        .size
        .checked_sub(16)
        .ok_or("OVMF firmware is too small")?;
    fw_info.start = rv_info
        .vector_address
        .checked_sub(vector_off)
        .ok_or("Cannot parse OVMF reset vector: invalid vector")?;
    Ok(rv_info.compatibility_mask)
}

fn parse_inner_table<'a>(
    data: &'a [u8],
    fw_img: &[u8],
    fw_info: &mut GuestFwInfoBlock,
    compat_mask: &mut u32,
) -> Result<&'a [u8], Box<dyn Error>> {
    let (uuid, body, remainder) = read_table(data)?;

    match uuid {
        OVMF_SEV_METADATA_GUID => parse_metadata(body, fw_img, &mut SevMetadata {}, fw_info)?,
        SEV_INFO_BLOCK_GUID => parse_sev_info_block(body, fw_info)?,
        OVMF_TDX_METADATA_GUID => parse_metadata(body, fw_img, &mut TdxMetadata {}, fw_info)?,
        OVMF_IGVM_METADATA_GUID => parse_metadata(body, fw_img, &mut IgvmMetadata::new(), fw_info)?,
        OVMF_RESET_VECTOR_GUID => *compat_mask = parse_reset_vector(body, fw_info)?,
        _ => {}
    }
    Ok(remainder)
}

fn check_regions(fw_info: &GuestFwInfoBlock) -> Result<(), Box<dyn Error>> {
    let flash_range = {
        let one_gib = 1u32 << 30;
        (3 * one_gib, one_gib) // (start, size)
    };
    if !region_contains(flash_range, (fw_info.start, fw_info.size)) {
        return Err("OVMF firmware not located in expected flash range".into());
    }

    let preval_count = fw_info.prevalidated_count as usize;
    let regions = &fw_info.prevalidated[..preval_count];
    // Make sure that regions don't overlap.
    for (i, region) in regions.iter().enumerate() {
        for other in regions[..i].iter() {
            if region_overlaps((region.base, region.size), (other.base, other.size)) {
                let (rbase, rsize) = (region.base, region.size);
                let (obase, osize) = (other.base, other.size);
                return Err(format!(
                    "OVMF pre-validated regions overlap: [{:#x}-{:#x}] | [{:#x}-{:#x}]",
                    rbase,
                    rbase as u64 + rsize as u64,
                    obase,
                    obase as u64 + osize as u64
                )
                .into());
            }
        }
    }
    Ok(())
}

pub fn parse_ovmf(
    data: &[u8],
    fw_info: &mut GuestFwInfoBlock,
    compat_mask: &mut u32,
) -> Result<(), Box<dyn Error>> {
    // The OVMF metadata UUID is stored at a specific offset from the end of the file.
    if data.len() < FOOTER_OFFSET {
        return Err("OVMF firmware file is too small".into());
    }
    let (uuid, mut body, _) = read_table(&data[..data.len() - FOOTER_OFFSET])?;
    if uuid != OVMF_TABLE_FOOTER_GUID {
        return Err("OVMF table footer not found".into());
    }

    while !body.is_empty() {
        body = parse_inner_table(body, data, fw_info, compat_mask)?;
    }
    check_regions(fw_info)
}

pub struct OvmfFirmware {
    fw_info: GuestFwInfoBlock,
    directives: Vec<IgvmDirectiveHeader>,
}

impl OvmfFirmware {
    pub fn parse(
        filename: &String,
        _parameter_count: u32,
        compatibility_mask: u32,
    ) -> Result<Box<dyn Firmware>, Box<dyn Error>> {
        let mut in_file = File::open(filename).inspect_err(|_| {
            eprintln!("Failed to open firmware file {filename}");
        })?;
        // Must fit within the 32-bit address space.
        let len = u32::try_from(in_file.metadata()?.len())
            .map_err(|_| "OVMF firmware is too large")? as usize;
        if len == 0 {
            return Err("OVMF firmware is empty".into());
        }
        let mut data = Vec::with_capacity(len);
        if in_file.read_to_end(&mut data)? != len {
            return Err("Failed to read OVMF file".into());
        }
        let mut fw_info = GuestFwInfoBlock {
            // OVMF is located to end at 4GB by default.
            // len is guaranteed not to overflow or underflow the result.
            start: ((1usize << 32) - len) as u32,
            size: len as u32,
            ..Default::default()
        };
        // OVMF is not compatible with TDP by default.
        let mut fw_compat_mask =
            compatibility_mask & (SNP_COMPATIBILITY_MASK | NATIVE_COMPATIBILITY_MASK);

        parse_ovmf(&data, &mut fw_info, &mut fw_compat_mask)?;

        if (fw_compat_mask & compatibility_mask) == 0 {
            return Err("OVMF file incompatible with the specified platform(s)".into());
        }

        // Build page directives for the file contents.
        let mut gpa: u64 = fw_info.start.into();
        let mut directives = Vec::<IgvmDirectiveHeader>::new();
        for page_data in data.chunks(PAGE_SIZE_4K as usize) {
            directives.push(IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: fw_compat_mask,
                flags: IgvmPageDataFlags::new(),
                data_type: IgvmPageDataType::NORMAL,
                data: page_data.to_vec(),
            });
            gpa += PAGE_SIZE_4K;
        }

        Ok(Box::new(Self {
            fw_info,
            directives,
        }))
    }
}

impl Firmware for OvmfFirmware {
    fn directives(&self) -> &Vec<IgvmDirectiveHeader> {
        &self.directives
    }

    fn get_guest_context(&self) -> Option<InitialGuestContext> {
        None
    }

    fn get_vtom(&self) -> u64 {
        0
    }

    fn get_fw_info(&self) -> &GuestFwInfoBlock {
        &self.fw_info
    }

    fn finalize_fw_info(&self, _gpa_map: &GpaMap) -> GuestFwInfoBlock {
        self.fw_info
    }
}
