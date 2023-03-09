// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::fw_cfg::FwCfg;
use crate::string::FixedString;
use alloc::alloc::{alloc, dealloc, handle_alloc_error};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem;
use core::ptr;
use log;

#[repr(C, packed)]
pub struct RSDPDesc {
    pub sig: [u8; 8],
    pub chksum: u8,
    pub oem_id: [u8; 6],
    pub rev: u8,
    pub rsdt_addr: u32,
}

impl RSDPDesc {
    pub const fn new() -> Self {
        RSDPDesc {
            sig: [0; 8],
            chksum: 0,
            oem_id: [0; 6],
            rev: 0,
            rsdt_addr: 0,
        }
    }

    pub fn load(&mut self, fw_cfg: &FwCfg) -> Result<(), ()> {
        let file = fw_cfg.file_selector("etc/acpi/rsdp")?;
        let size = file.size() as usize;

        if file.size() as usize != mem::size_of::<RSDPDesc>() {
            return Err(());
        }

        fw_cfg.select(file.selector());

        unsafe {
            let ptr = ptr::NonNull::new(self).unwrap();
            let buf_ptr = ptr.as_ptr().cast::<u8>();

            for i in 0..size {
                let byte: u8 = fw_cfg.read_le();
                buf_ptr.add(i).write(byte);
            }
        }

        Ok(())
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
    pub const fn new(raw: RawACPITableHeader) -> Self {
        ACPITableHeader {
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
    pub fn print_summary(&self) {
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
    fn new(ptr: *const u8) -> Result<Self, ()> {
        unsafe {
            let raw_header = ptr.cast::<RawACPITableHeader>();
            let size = (*raw_header).len as usize;

            let layout = Layout::array::<u8>(size).unwrap();
            let buf = ptr::NonNull::new(alloc(layout)).unwrap();

            ptr::copy(ptr, buf.as_ptr(), size);

            Ok(ACPITable {
                header: ACPITableHeader::new(*raw_header),
                ptr: buf,
                size: size,
            })
        }
    }

    #[allow(dead_code)]
    pub fn signature(&self) -> FixedString<4> {
        FixedString::from(self.header.sig)
    }

    pub fn content_length(&self) -> usize {
        if self.size <= mem::size_of::<RawACPITableHeader>() {
            0
        } else {
            self.size - mem::size_of::<RawACPITableHeader>()
        }
    }

    pub fn content(&mut self) -> *mut u8 {
        let offset = mem::size_of::<RawACPITableHeader>();

        unsafe { self.ptr.as_ptr().add(offset) }
    }
}

struct ACPITableMeta {
    pub sig: FixedString<4>,
    pub offset: usize,
}

impl ACPITableMeta {
    pub fn new(header: &RawACPITableHeader, offset: usize) -> Self {
        let sig = FixedString::from(header.sig);

        ACPITableMeta {
            sig: sig,
            offset: offset,
        }
    }
}

struct ACPITableBuffer {
    ptr: ptr::NonNull<u8>,
    size: usize,
    tables: Vec<ACPITableMeta>,
}

impl ACPITableBuffer {
    pub const fn new() -> Self {
        ACPITableBuffer {
            ptr: ptr::NonNull::dangling(),
            size: 0,
            tables: Vec::new(),
        }
    }

    fn load_tables(&mut self, fw_cfg: &FwCfg) -> Result<(), ()> {
        let mut desc: RSDPDesc = RSDPDesc::new();

        desc.load(fw_cfg)?;

        let mut rsdt = self.acpi_table_from_offset(desc.rsdt_addr as usize)?;
        let len = rsdt.content_length();

        if len == 0 {
            return Err(());
        }

        let entries = len / 4;

        let content = rsdt.content().cast::<u32>();

        for i in 0..entries {
            unsafe {
                let entry_ptr = content.add(i);
                let offset = (*entry_ptr) as usize;

                if offset + mem::size_of::<RawACPITableHeader>() >= self.size {
                    return Err(());
                }

                let raw_header = self.ptr.as_ptr().add(offset).cast::<RawACPITableHeader>();
                let meta = ACPITableMeta::new(raw_header.as_ref().unwrap(), offset);

                self.tables.push(meta);
            }
        }

        Ok(())
    }

    pub fn load_from_fwcfg(&mut self, fw_cfg: &FwCfg) -> Result<(), ()> {
        if self.size != 0 {
            return Err(());
        }

        let file = fw_cfg.file_selector("etc/acpi/tables")?;
        let size = file.size() as usize;

        unsafe {
            let layout = Layout::array::<u8>(size).unwrap();
            let ptr = match ptr::NonNull::new(alloc(layout)) {
                Some(p) => p,
                None => handle_alloc_error(layout),
            };

            self.ptr = ptr::NonNull::new(ptr.as_ptr()).unwrap();
            self.size = size;

            fw_cfg.select(file.selector());
            for i in 0..size {
                let byte: u8 = fw_cfg.read_le();
                ptr.as_ptr().add(i).write(byte);
            }
        }

        self.load_tables(fw_cfg)
            .expect("Loading ACPI tables failed");

        Ok(())
    }

    fn acpi_table_from_offset(&self, offset: usize) -> Result<ACPITable, ()> {
        if offset + mem::size_of::<RawACPITableHeader>() >= self.size {
            return Err(());
        }

        unsafe {
            let ptr = self.ptr.as_ptr().add(offset);
            ACPITable::new(ptr)
        }
    }

    pub fn acp_table_by_sig(&self, sig: &str) -> Option<ACPITable> {
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

pub const MADT_HEADER_SIZE: usize = 8;

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

pub fn load_acpi_cpu_info(fw_cfg: &FwCfg) -> Result<Vec<ACPICPUInfo>, ()> {
    let mut buffer = ACPITableBuffer::new();

    buffer.load_from_fwcfg(fw_cfg)?;

    let mut apic_table = buffer
        .acp_table_by_sig("APIC")
        .expect("MADT ACPI table not found");
    let len = apic_table.content_length();

    if len == 0 {
        return Err(());
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
