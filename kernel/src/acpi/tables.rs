// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use alloc::string::{FromUtf8Error, String};
use alloc::vec::Vec;
use core::mem;
use core::str;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

/// ACPI Root System Description Pointer (RSDP)
/// used by ACPI programming interface
#[derive(Debug, Default, FromBytes, IntoBytes)]
#[repr(C, packed)]
struct RSDPDesc {
    /// Signature must contain "RSD PTR"
    sig: [u8; 8],
    /// Checksum to add to all other bytes
    chksum: u8,
    /// OEM-supplied string
    oem_id: [u8; 6],
    /// Revision of the ACPI
    rev: u8,
    /// Physical address of the RSDT
    rsdt_addr: u32,
}

impl RSDPDesc {
    /// Create an RSPDesc instance from FwCfg
    ///
    /// # Arguments
    ///
    /// - `fw_cfg`: A reference to the FwCfg instance.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`RSDPDesc`] if successful, or an [`SvsmError`] on failure.
    fn from_fwcfg(fw_cfg: &FwCfg<'_>) -> Result<Self, SvsmError> {
        let path = option_env!("ACPI_RSDP_PATH").unwrap_or("etc/acpi/rsdp");
        let file = fw_cfg.file_selector(path)?;

        if (file.size() as usize) < mem::size_of::<Self>() {
            return Err(SvsmError::Acpi);
        }

        fw_cfg.select(file.selector());
        let mut this = Self::new_zeroed();
        fw_cfg.read_bytes(this.as_mut_bytes());
        Ok(this)
    }
}

#[derive(Copy, Clone, Debug, Default, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
/// Raw header of an ACPI table. It corresponds to the beginning
/// portion of ACPI tables, before any specific table data
struct RawACPITableHeader {
    /// Signature specificies the type of ACPI table
    sig: [u8; 4],
    /// Length of the table
    len: u32,
    /// Revision (signature field)
    rev: u8,
    /// Checksum for data integrity
    chksum: u8,
    /// OEM-supplied string to identify OEM
    oem_id: [u8; 6],
    /// OEM-supplied string to identify tables
    oem_table_id: [u8; 8],
    /// OEM-supplied version number
    oem_rev: u32,
    /// ID for compiler
    compiler_id: [u8; 4],
    /// Revision of compiler used to create the table
    compiler_rev: u32,
}

#[derive(Debug, Default)]
/// Higher level representation of the raw ACPI table header
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
    /// Create a new [`ACPITableHeader`] from a raw [`RawACPITableHeader`].
    ///
    /// This constructor converts a raw ACPI table header into a higher-level [`ACPITableHeader`].
    ///
    /// # Arguments
    ///
    /// * `raw` - A [`RawACPITableHeader`] containing the raw header data.
    ///
    /// # Returns
    ///
    /// A new [`ACPITableHeader`] instance.
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

    /// Print a human-readable summary of the ACPI table header's fields
    #[expect(dead_code)]
    fn print_summary(&self) -> Result<(), str::Utf8Error> {
        let sig = str::from_utf8(&self.sig)?;
        let oem_id = str::from_utf8(&self.oem_id)?;
        let oem_table_id = str::from_utf8(&self.oem_table_id)?;
        let compiler_id = str::from_utf8(&self.compiler_id)?;
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
        Ok(())
    }
}

#[derive(Debug)]
/// ACPI table, both header and contents
pub struct ACPITable {
    header: ACPITableHeader,
    /// Raw binary content of ACPI table
    buf: Vec<u8>,
}

impl ACPITable {
    /// Create a new [`ACPITable`] from raw binary data.
    ///
    /// This constructor creates an [`ACPITable`] instance by parsing raw binary data.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A slice containing the raw binary data of the ACPI table.
    ///
    /// # Returns
    ///
    /// A new [`ACPITable`] instance on success, or an [`SvsmError`] if parsing fails.
    pub fn new(ptr: &[u8]) -> Result<Self, SvsmError> {
        let (raw_header, _) =
            RawACPITableHeader::read_from_prefix(ptr).map_err(|_| SvsmError::Acpi)?;
        let size = raw_header.len as usize;
        let content = ptr.get(..size).ok_or(SvsmError::Acpi)?;

        let mut buf = Vec::<u8>::new();
        // Allow for a failable allocation before copying
        buf.try_reserve(size).map_err(|_| SvsmError::Mem)?;
        buf.extend_from_slice(content);

        let header = ACPITableHeader::new(raw_header);

        Ok(Self { header, buf })
    }

    /// Get the signature of the ACPI table.
    ///
    /// This method returns the 4-character signature of the ACPI table, such as "APIC."
    #[expect(dead_code)]
    fn signature(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(Vec::from(&self.header.sig))
    }

    /// Get the content of the ACPI table.
    ///
    /// This method returns a reference to the binary content of the ACPI table,
    /// excluding the header.
    ///
    /// # Returns
    ///
    /// A reference to the ACPI table content, or [`None`] if the content is empty.
    fn content(&self) -> Option<&[u8]> {
        let offset = mem::size_of::<RawACPITableHeader>();
        // Zero-length slices are valid, but we do not want them
        self.buf.get(offset..).filter(|b| !b.is_empty())
    }

    /// Get a pointer to the content of the ACPI table at a specific offset.
    ///
    /// This method returns a pointer to the content of the ACPI table at the specified offset,
    /// converted to the desired type `T`.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset at which to obtain the pointer.
    ///
    /// # Returns
    ///
    /// A reference to the content of the ACPI table at specified offset as type `T`,
    /// or [`None`] if the offset is out of bounds.
    fn content_ptr<T>(&self, offset: usize) -> Option<&T>
    where
        T: FromBytes + KnownLayout + Immutable,
    {
        let bytes = self.content()?.get(offset..)?;
        T::ref_from_prefix(bytes).ok().map(|(value, _rest)| value)
    }
}

/// ACPI Table Metadata
/// Metadata associated with an ACPI, information about signature and offset
#[derive(Debug)]
struct ACPITableMeta {
    /// 4-character signature of the table
    sig: String,
    /// The offset of the table within the table buffer
    offset: usize,
}

impl ACPITableMeta {
    /// Create a new [`ACPITableMeta`] instance.
    ///
    /// This constructor creates an [`ACPITableMeta`] instance with the specified signature and offset.
    ///
    /// # Arguments
    ///
    /// * `header` - The raw ACPI table header containing the signature.
    /// * `offset` - The offset of the ACPI table within the ACPI table buffer.
    ///
    /// # Returns
    ///
    /// A new [`ACPITableMeta`] instance.
    fn new(header: &RawACPITableHeader, offset: usize) -> Result<Self, SvsmError> {
        let sig = String::from_utf8(Vec::from(&header.sig)).map_err(|_| SvsmError::Acpi)?;
        Ok(Self { sig, offset })
    }
}

const MAX_ACPI_TABLES_SIZE: usize = 128 * 1024;

/// ACPI Table Buffer
/// A buffer containing ACPI tables. Responsible for loading the tables
/// from a firmware configuration
#[derive(Debug)]
struct ACPITableBuffer {
    buf: Vec<u8>,
    /// Collection of metadata for ACPI tables, including signatures
    tables: Vec<ACPITableMeta>,
}

impl ACPITableBuffer {
    /// Create a new [`ACPITableBuffer`] instance from a firmware configuration source.
    ///
    /// This constructor creates an [`ACPITableBuffer`] instance by reading ACPI tables from the specified FwCfg source.
    ///
    /// # Arguments
    ///
    /// * `fw_cfg` - The firmware configuration source (FwCfg) from which ACPI tables will be loaded.
    ///
    /// # Returns
    ///
    /// A new [`ACPITableBuffer`] instance containing ACPI tables and their metadata.
    fn from_fwcfg(fw_cfg: &FwCfg<'_>) -> Result<Self, SvsmError> {
        let path = option_env!("ACPI_TABLES_PATH").unwrap_or("etc/acpi/tables");
        let file = fw_cfg.file_selector(path)?;
        let size = file.size() as usize;

        let mut buf = Vec::<u8>::new();
        if size > MAX_ACPI_TABLES_SIZE {
            return Err(SvsmError::Mem);
        }
        buf.try_reserve(size).map_err(|_| SvsmError::Mem)?;
        buf.resize(size, 0);
        fw_cfg.select(file.selector());
        fw_cfg.read_bytes(&mut buf);

        let mut acpibuf = Self {
            buf,
            tables: Vec::new(),
        };
        acpibuf.load_tables(fw_cfg)?;
        Ok(acpibuf)
    }

    /// Load ACPI tables and their metadata from the ACPI Root System Description Pointer (RSDP).
    ///
    /// This method populates the `tables` field of the [`ACPITableBuffer`] with metadata for ACPI tables
    /// found within the ACPI Root System Description Pointer (RSDP) structure.
    ///
    /// # Arguments
    ///
    /// * `fw_cfg` - The firmware configuration source (FwCfg) containing ACPI tables.
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success or an error if ACPI tables cannot be loaded.
    fn load_tables(&mut self, fw_cfg: &FwCfg<'_>) -> Result<(), SvsmError> {
        let desc = RSDPDesc::from_fwcfg(fw_cfg)?;

        let rsdt = self.acpi_table_from_offset(desc.rsdt_addr as usize)?;
        let content = rsdt.content().ok_or(SvsmError::Acpi)?;
        let offsets = content
            .chunks_exact(mem::size_of::<u32>())
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()) as usize);

        for offset in offsets {
            let raw_header = self.buf.get(offset..).ok_or(SvsmError::Acpi)?;
            let (raw_header, _) =
                RawACPITableHeader::ref_from_prefix(raw_header).map_err(|_| SvsmError::Acpi)?;
            let meta = ACPITableMeta::new(raw_header, offset)?;
            self.tables.push(meta);
        }

        Ok(())
    }

    /// Retrieve an ACPI table from a specified offset within the ACPI table buffer.
    ///
    /// This function attempts to retrieve an ACPI table from the ACPI table buffer starting from the
    /// specified offset. It parses the table header and creates an [`ACPITable`] instance representing
    /// the ACPI table's content.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset within the ACPI table buffer from which to retrieve the ACPI table.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`ACPITable`] instance if successfully retrieved, or an [`SvsmError`]
    /// if the table cannot be retrieved or parsed.
    fn acpi_table_from_offset(&self, offset: usize) -> Result<ACPITable, SvsmError> {
        let buf = self.buf.get(offset..).ok_or(SvsmError::Acpi)?;
        ACPITable::new(buf)
    }

    /// Retrieve an ACPI table by its signature.
    ///
    /// This method attempts to retrieve an ACPI table by its 4-character signature.
    ///
    /// # Arguments
    ///
    /// * `sig` - The signature of the ACPI table to retrieve.
    ///
    /// # Returns
    ///
    /// An [`Option`] containing the ACPI table if found, or [`None`] if not found.
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

/// Header of an entry within MADT
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMADTEntryHeader {
    entry_type: u8,
    entry_len: u8,
}

/// Entry for a local APIC within MADT
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMADTEntryLocalApic {
    header: RawMADTEntryHeader,
    acpi_id: u8,
    apic_id: u8,
    flags: u32,
}

/// Entry for a local X2APIC within MADT
#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMADTEntryLocalX2Apic {
    header: RawMADTEntryHeader,
    reserved: [u8; 2],
    apic_id: u32,
    flags: u32,
    acpi_id: u32,
}

/// Information about an ACPI CPU
#[derive(Clone, Copy, Debug)]
pub struct ACPICPUInfo {
    /// The APIC ID for the CPU
    pub apic_id: u32,
    /// Indicates whether the CPU is enabled
    pub enabled: bool,
}

/// Loads ACPI CPU information by parsing the ACPI tables provided by the firmware
/// It processes the Multiple APIC Description Table (MADT) to extract information about each CPU's
/// APIC ID and enabled status.
///
/// # Arguments
///
/// * `fw_cfg`: A reference to the Firmware Configuration (FwCfg) interface for accessing ACPI tables.
///
/// # Returns
///
/// A [`Result`] containing a vector of [`ACPICPUInfo`] structs representing CPU information.
/// If successful, the vector contains information about each detected CPU; otherwise, an error is returned.
///
/// # Errors
///
/// This function returns an error if there are issues with reading or parsing ACPI tables,
/// or if the required ACPI tables are not found.
///
/// # Example
///
/// ```
/// use svsm::acpi::tables::load_fw_cpu_info;
/// use svsm::fw_cfg::FwCfg;
/// use svsm::io::IOPort;
///
/// #[derive(Debug)]
/// struct MyIo;
///
/// impl IOPort for MyIo {
///     // your implementation
/// #     fn outb(&self, _port: u16, _value: u8) {}
/// #     fn outw(&self, _port: u16, _value: u16) {}
/// #     fn inb(&self, _port: u16) -> u8 { 0 }
/// #     fn inw(&self, _port: u16) -> u16 { 0 }
/// }
///
/// let io = MyIo;
/// let fw_cfg = FwCfg::new(&io);
/// match load_fw_cpu_info(&fw_cfg) {
///     Ok(cpu_info) => {
///         for info in cpu_info {
///             // You can print id (info.apic_id) and whether it is enabled (info.enabled)
///         }
///     }
///     Err(err) => {
///         // Print error
///     }
/// }
/// ```
pub fn load_fw_cpu_info(fw_cfg: &FwCfg<'_>) -> Result<Vec<ACPICPUInfo>, SvsmError> {
    let buffer = ACPITableBuffer::from_fwcfg(fw_cfg)?;

    let apic_table = buffer.acp_table_by_sig("APIC").ok_or(SvsmError::Acpi)?;
    load_acpi_cpu_info(&apic_table)
}

/// Loads ACPI CPU information by parsing the ACPI tables.
/// It processes the Multiple APIC Description Table (MADT) to extract information about each CPU's
/// APIC ID and enabled status.
///
/// # Arguments
///
/// * 'apic_table': A reference to the MADT that was located from the ACPI tables.
///
/// # Returns
///
/// A [`Result`] containing a vector of [`ACPICPUInfo`] structs representing CPU information.
/// If successful, the vector contains information about each detected CPU; otherwise, an error is returned.
///
/// # Errors
///
/// This function returns an error if there are issues with reading or parsing ACPI tables.
pub fn load_acpi_cpu_info(apic_table: &ACPITable) -> Result<Vec<ACPICPUInfo>, SvsmError> {
    let content = apic_table.content().ok_or(SvsmError::Acpi)?;
    let mut cpus: Vec<ACPICPUInfo> = Vec::new();

    let mut offset = MADT_HEADER_SIZE;
    while offset < content.len() {
        let entry_ptr = apic_table
            .content_ptr::<RawMADTEntryHeader>(offset)
            .ok_or(SvsmError::Acpi)?;
        let entry_len = usize::from(entry_ptr.entry_len);

        match entry_ptr.entry_type {
            0 if entry_len == mem::size_of::<RawMADTEntryLocalApic>() => {
                let lapic_ptr = apic_table
                    .content_ptr::<RawMADTEntryLocalApic>(offset)
                    .ok_or(SvsmError::Acpi)?;
                cpus.push(ACPICPUInfo {
                    apic_id: lapic_ptr.apic_id as u32,
                    enabled: (lapic_ptr.flags & 1) == 1,
                });
            }
            9 if entry_len == mem::size_of::<RawMADTEntryLocalX2Apic>() => {
                let x2apic_ptr = apic_table
                    .content_ptr::<RawMADTEntryLocalX2Apic>(offset)
                    .ok_or(SvsmError::Acpi)?;
                cpus.push(ACPICPUInfo {
                    apic_id: x2apic_ptr.apic_id,
                    enabled: (x2apic_ptr.flags & 1) == 1,
                });
            }
            madt_type if entry_len == 0 => {
                log::warn!(
                    "Found zero-length MADT entry with type {}, stopping",
                    madt_type
                );
                break;
            }
            madt_type => {
                log::info!("Ignoring MADT entry with type {}", madt_type);
            }
        }

        offset = offset.checked_add(entry_len).ok_or(SvsmError::Acpi)?;
    }

    Ok(cpus)
}
