// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::string::FixedString;
use alloc::alloc::{alloc, dealloc, handle_alloc_error};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem;
use core::ptr;
use log;

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

#[derive(Copy, Clone)]
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

struct ACPITable {
    header: ACPITableHeader,
    ptr: ptr::NonNull<u8>,
    size: usize,
}

impl ACPITable {
    fn new(ptr: *const u8) -> Result<Self, SvsmError> {
        unsafe {
            let raw_header = ptr.cast::<RawACPITableHeader>();
            let size = (*raw_header).len as usize;

            let layout = Layout::array::<u8>(size).map_err(|_| SvsmError::Mem)?;
            let buf =
                ptr::NonNull::new(alloc(layout)).unwrap_or_else(|| handle_alloc_error(layout));

            ptr::copy(ptr, buf.as_ptr(), size);

            Ok(Self {
                header: ACPITableHeader::new(*raw_header),
                ptr: buf,
                size: size,
            })
        }
    }

    #[allow(dead_code)]
    fn signature(&self) -> FixedString<4> {
        FixedString::from(self.header.sig)
    }

    fn content_length(&self) -> usize {
        self.size
            .saturating_sub(mem::size_of::<RawACPITableHeader>())
    }

    fn content(&self) -> *const u8 {
        let offset = mem::size_of::<RawACPITableHeader>();

        unsafe { self.ptr.as_ptr().add(offset) }
    }
}

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

struct ACPITableBuffer {
    ptr: ptr::NonNull<u8>,
    size: usize,
    tables: Vec<ACPITableMeta>,
}

impl ACPITableBuffer {
    fn from_fwcfg(fw_cfg: &FwCfg) -> Result<Self, SvsmError> {
        let file = fw_cfg.file_selector("etc/acpi/tables")?;
        let size = file.size() as usize;

        let layout = Layout::array::<u8>(size).map_err(|_| SvsmError::Mem)?;
        let ptr = unsafe { alloc(layout) };
        let ptr = ptr::NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));

        fw_cfg.select(file.selector());
        for i in 0..size {
            let byte: u8 = fw_cfg.read_le();
            unsafe { ptr.as_ptr().add(i).write(byte) };
        }

        let mut buf = Self {
            ptr,
            size,
            tables: Vec::new(),
        };
        buf.load_tables(fw_cfg)?;
        Ok(buf)
    }

    fn load_tables(&mut self, fw_cfg: &FwCfg) -> Result<(), SvsmError> {
        let desc = RSDPDesc::from_fwcfg(fw_cfg)?;

        let rsdt = self.acpi_table_from_offset(desc.rsdt_addr as usize)?;
        let len = rsdt.content_length();

        if len == 0 {
            return Err(SvsmError::Acpi);
        }

        let entries = len / 4;

        let content = rsdt.content().cast::<u32>();

        for i in 0..entries {
            unsafe {
                let entry_ptr = content.add(i);
                let offset = (*entry_ptr) as usize;

                if offset + mem::size_of::<RawACPITableHeader>() >= self.size {
                    return Err(SvsmError::Acpi);
                }

                let raw_header = self.ptr.as_ptr().add(offset).cast::<RawACPITableHeader>();
                let meta = ACPITableMeta::new(raw_header.as_ref().unwrap(), offset);

                self.tables.push(meta);
            }
        }

        Ok(())
    }

    fn acpi_table_from_offset(&self, offset: usize) -> Result<ACPITable, SvsmError> {
        if offset + mem::size_of::<RawACPITableHeader>() >= self.size {
            return Err(SvsmError::Acpi);
        }

        unsafe {
            let ptr = self.ptr.as_ptr().add(offset);
            ACPITable::new(ptr)
        }
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

impl Drop for ACPITableBuffer {
    fn drop(&mut self) {
        if self.size != 0 {
            unsafe {
                let layout = Layout::array::<u8>(self.size).unwrap();
                dealloc(self.ptr.as_ptr(), layout);
            }
        }
    }
}

const MADT_HEADER_SIZE: usize = 8;

#[allow(dead_code)]
#[repr(C, packed)]
struct RawMADTEntryHeader {
    entry_type: u8,
    entry_len: u8,
}

#[allow(dead_code)]
#[repr(C, packed)]
struct RawMADTEntryLocalApic {
    header: RawMADTEntryHeader,
    acpi_id: u8,
    apic_id: u8,
    flags: u32,
}

#[allow(dead_code)]
#[repr(C, packed)]
struct RawMADTEntryLocalX2Apic {
    header: RawMADTEntryHeader,
    reserved: [u8; 2],
    apic_id: u32,
    flags: u32,
    acpi_id: u32,
}

pub struct ACPICPUInfo {
    pub apic_id: u32,
    pub enabled: bool,
}

pub fn load_acpi_cpu_info(fw_cfg: &FwCfg) -> Result<Vec<ACPICPUInfo>, SvsmError> {
    let buffer = ACPITableBuffer::from_fwcfg(fw_cfg)?;

    let apic_table = buffer.acp_table_by_sig("APIC").ok_or(SvsmError::Acpi)?;
    let len = apic_table.content_length();

    if len == 0 {
        return Err(SvsmError::Acpi);
    }

    let content = apic_table.content();

    let mut cpus: Vec<ACPICPUInfo> = Vec::new();

    unsafe {
        let mut offset = MADT_HEADER_SIZE;
        while offset < len {
            let entry_ptr = content.add(offset).cast::<RawMADTEntryHeader>();
            let t: u8 = (*entry_ptr).entry_type;
            let l: u8 = (*entry_ptr).entry_len;
            offset += l as usize;
            if t == 0 {
                let lapic_ptr = entry_ptr.cast::<RawMADTEntryLocalApic>();
                let apic_id: u32 = (*lapic_ptr).apic_id as u32;
                let flags: u32 = (*lapic_ptr).flags;
                cpus.push(ACPICPUInfo {
                    apic_id: apic_id,
                    enabled: (flags & 1) == 1,
                });
            } else if t == 9 {
                let x2apic_ptr = entry_ptr.cast::<RawMADTEntryLocalX2Apic>();
                let apic_id: u32 = (*x2apic_ptr).apic_id as u32;
                let flags: u32 = (*x2apic_ptr).flags;
                cpus.push(ACPICPUInfo {
                    apic_id: apic_id,
                    enabled: (flags & 1) == 1,
                });
            }
        }
    }

    Ok(cpus)
}
