// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::string::FixedString;
use alloc::vec::Vec;
use core::mem;
use log;

#[derive(Debug, Default)]
#[repr(C, packed)]
struct RSDPDesc {
    sig: [u8; 8],
    chksum: u8,
    oem_id: [u8; 6],
    rev: u8,
    rsdt_addr: u32,
}

impl RSDPDesc {
    fn from_fwcfg(fw_cfg: &FwCfg) -> Result<Self, SvsmError> {
        let mut buf = mem::MaybeUninit::<Self>::uninit();
        let file = fw_cfg.file_selector("etc/acpi/rsdp")?;
        let size = file.size() as usize;

        if size != mem::size_of::<Self>() {
            return Err(SvsmError::Acpi);
        }

        fw_cfg.select(file.selector());
        let ptr = buf.as_mut_ptr().cast::<u8>();
        for i in 0..size {
            let byte: u8 = fw_cfg.read_le();
            unsafe { ptr.add(i).write(byte) };
        }

        unsafe { Ok(buf.assume_init()) }
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct RawACPITableHeader {
    sig: [u8; 4],
    len: u32,
    rev: u8,
    chksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_rev: u32,
    compiler_id: [u8; 4],
    compiler_rev: u32,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct ACPITableHeader {
    sig: [u8; 4],
    len: u32,
    rev: u8,
    chksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_rev: u32,
    compiler_id: [u8; 4],
    compiler_rev: u32,
}

impl ACPITableHeader {
    const fn new(raw: RawACPITableHeader) -> Self {
        Self {
            sig: raw.sig,
            len: raw.len,
            rev: raw.rev,
            chksum: raw.chksum,
            oem_id: raw.oem_id,
            oem_table_id: raw.oem_table_id,
            oem_rev: raw.oem_rev,
            compiler_id: raw.compiler_id,
            compiler_rev: raw.compiler_rev,
        }
    }

    #[allow(dead_code)]
    fn print_summary(&self) {
        let sig = FixedString::from(self.sig);
        let oem_id = FixedString::from(self.oem_id);
        let oem_table_id = FixedString::from(self.oem_table_id);
        let compiler_id = FixedString::from(self.compiler_id);
        log::trace!(
            "ACPI: [{} {} {} {} {} {} {} {} {}]",
            sig,
            self.len,
            self.rev,
            self.chksum,
            oem_id,
            oem_table_id,
            self.oem_rev,
            compiler_id,
            self.compiler_rev
        );
    }
}

#[derive(Debug)]
struct ACPITable {
    header: ACPITableHeader,
    buf: Vec<u8>,
}

impl ACPITable {
    fn new(ptr: &[u8]) -> Result<Self, SvsmError> {
        let raw_header = ptr
            .get(..mem::size_of::<RawACPITableHeader>())
            .ok_or(SvsmError::Acpi)?
            .as_ptr()
            .cast::<RawACPITableHeader>();
        let size = unsafe { (*raw_header).len as usize };
        let content = ptr.get(..size).ok_or(SvsmError::Acpi)?;

        let mut buf = Vec::<u8>::new();
        // Allow for a failable allocation before copying
        buf.try_reserve(size).map_err(|_| SvsmError::Mem)?;
        buf.extend_from_slice(content);

        let header = unsafe { ACPITableHeader::new(*raw_header) };

        Ok(Self { header, buf })
    }

    #[allow(dead_code)]
    fn signature(&self) -> FixedString<4> {
        FixedString::from(self.header.sig)
    }

    fn content(&self) -> Option<&[u8]> {
        let offset = mem::size_of::<RawACPITableHeader>();
        // Zero-length slices are valid, but we do not want them
        self.buf.get(offset..).filter(|b| !b.is_empty())
    }

    fn content_ptr<T>(&self, offset: usize) -> Option<*const T> {
        let end = offset.checked_add(mem::size_of::<T>())?;
        Some(self.content()?.get(offset..end)?.as_ptr().cast::<T>())
    }
}

#[derive(Debug)]
struct ACPITableMeta {
    sig: FixedString<4>,
    offset: usize,
}

impl ACPITableMeta {
    fn new(header: &RawACPITableHeader, offset: usize) -> Self {
        let sig = FixedString::from(header.sig);
        Self { sig, offset }
    }
}

#[derive(Debug)]
struct ACPITableBuffer {
    buf: Vec<u8>,
    tables: Vec<ACPITableMeta>,
}

impl ACPITableBuffer {
    fn from_fwcfg(fw_cfg: &FwCfg) -> Result<Self, SvsmError> {
        let file = fw_cfg.file_selector("etc/acpi/tables")?;
        let size = file.size() as usize;

        let mut buf = Vec::<u8>::new();
        buf.try_reserve(size).map_err(|_| SvsmError::Mem)?;
        let ptr = buf.as_mut_ptr();

        fw_cfg.select(file.selector());
        for i in 0..size {
            let byte: u8 = fw_cfg.read_le();
            unsafe { ptr.add(i).write(byte) };
        }
        unsafe { buf.set_len(size) }

        let mut acpibuf = Self {
            buf,
            tables: Vec::new(),
        };
        acpibuf.load_tables(fw_cfg)?;
        Ok(acpibuf)
    }

    fn load_tables(&mut self, fw_cfg: &FwCfg) -> Result<(), SvsmError> {
        let desc = RSDPDesc::from_fwcfg(fw_cfg)?;

        let rsdt = self.acpi_table_from_offset(desc.rsdt_addr as usize)?;
        let content = rsdt.content().ok_or(SvsmError::Acpi)?;
        let offsets = content
            .chunks_exact(mem::size_of::<u32>())
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()) as usize);

        for offset in offsets {
            let raw_header = offset
                .checked_add(mem::size_of::<RawACPITableHeader>())
                .and_then(|end| self.buf.get(offset..end))
                .ok_or(SvsmError::Acpi)?
                .as_ptr()
                .cast::<RawACPITableHeader>();

            let meta = unsafe { ACPITableMeta::new(&*raw_header, offset) };

            self.tables.push(meta);
        }

        Ok(())
    }

    fn acpi_table_from_offset(&self, offset: usize) -> Result<ACPITable, SvsmError> {
        let buf = self.buf.get(offset..).ok_or(SvsmError::Acpi)?;
        ACPITable::new(buf)
    }

    fn acp_table_by_sig(&self, sig: &str) -> Option<ACPITable> {
        let offset = self
            .tables
            .iter()
            .find(|entry| entry.sig == sig)
            .map(|entry| entry.offset)?;

        self.acpi_table_from_offset(offset).ok()
    }
}

const MADT_HEADER_SIZE: usize = 8;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
#[repr(C, packed)]
struct RawMADTEntryHeader {
    entry_type: u8,
    entry_len: u8,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
#[repr(C, packed)]
struct RawMADTEntryLocalApic {
    header: RawMADTEntryHeader,
    acpi_id: u8,
    apic_id: u8,
    flags: u32,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
#[repr(C, packed)]
struct RawMADTEntryLocalX2Apic {
    header: RawMADTEntryHeader,
    reserved: [u8; 2],
    apic_id: u32,
    flags: u32,
    acpi_id: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ACPICPUInfo {
    pub apic_id: u32,
    pub enabled: bool,
}

pub fn load_acpi_cpu_info(fw_cfg: &FwCfg) -> Result<Vec<ACPICPUInfo>, SvsmError> {
    let buffer = ACPITableBuffer::from_fwcfg(fw_cfg)?;

    let apic_table = buffer.acp_table_by_sig("APIC").ok_or(SvsmError::Acpi)?;
    let content = apic_table.content().ok_or(SvsmError::Acpi)?;

    let mut cpus: Vec<ACPICPUInfo> = Vec::new();

    let mut offset = MADT_HEADER_SIZE;
    while offset < content.len() {
        let entry_ptr = apic_table
            .content_ptr::<RawMADTEntryHeader>(offset)
            .ok_or(SvsmError::Acpi)?;
        let (madt_type, entry_len) = unsafe { ((*entry_ptr).entry_type, (*entry_ptr).entry_len) };
        let entry_len = usize::from(entry_len);

        match madt_type {
            0 if entry_len == mem::size_of::<RawMADTEntryLocalApic>() => {
                let lapic_ptr = apic_table
                    .content_ptr::<RawMADTEntryLocalApic>(offset)
                    .ok_or(SvsmError::Acpi)?;
                let (apic_id, flags) = unsafe { ((*lapic_ptr).apic_id as u32, (*lapic_ptr).flags) };
                cpus.push(ACPICPUInfo {
                    apic_id,
                    enabled: (flags & 1) == 1,
                });
            }
            9 if entry_len == mem::size_of::<RawMADTEntryLocalX2Apic>() => {
                let x2apic_ptr = apic_table
                    .content_ptr::<RawMADTEntryLocalX2Apic>(offset)
                    .ok_or(SvsmError::Acpi)?;
                let (apic_id, flags) = unsafe { ((*x2apic_ptr).apic_id, (*x2apic_ptr).flags) };
                cpus.push(ACPICPUInfo {
                    apic_id,
                    enabled: (flags & 1) == 1,
                });
            }
            _ if entry_len == 0 => {
                log::warn!(
                    "Found zero-length MADT entry with type {}, stopping",
                    madt_type
                );
                break;
            }
            _ => {
                log::info!("Ignoring MADT entry with type {}", madt_type);
            }
        }

        offset = offset.checked_add(entry_len).ok_or(SvsmError::Acpi)?;
    }

    Ok(cpus)
}
