// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::Elf64AddrRange;
use super::Elf64File;
use super::Elf64FileRange;
use super::ElfError;
use bitflags::bitflags;

bitflags! {
    /// Flags associated with ELF64 section header (e.g.,
    /// writable, contains null-terminated string, etc.
    #[derive(Debug)]
    pub struct Elf64ShdrFlags : Elf64Xword {
        const WRITE            = 0x001;
        const ALLOC            = 0x002;
        const EXECINSTR        = 0x004;
        const MERGE            = 0x010;
        const STRINGS          = 0x020;
        const INFO_LINK        = 0x040;
        const LINK_ORDER       = 0x080;
        const OS_NONCONFORMING = 0x100;
        const GROUP            = 0x200;
        const TLS              = 0x400;
        const COMPRESSED       = 0x800;
    }
}

/// An ELF64 section header
#[derive(Debug)]
pub struct Elf64Shdr {
    pub sh_name: Elf64Word,
    pub sh_type: Elf64Word,
    pub sh_flags: Elf64ShdrFlags,
    pub sh_addr: Elf64Addr,
    pub sh_offset: Elf64Off,
    /// Size of the section
    pub sh_size: Elf64Xword,
    /// Link to another section
    pub sh_link: Elf64Word,
    /// Additional section information
    pub sh_info: Elf64Word,
    /// Address alignment constraint
    pub sh_addralign: Elf64Xword,
    /// Size of each entry
    pub sh_entsize: Elf64Xword,
}

impl Elf64Shdr {
    /// Represents an undefined section index
    pub const SHN_UNDEF: Elf64Word = 0;

    /// Represents an absolute section index
    pub const SHN_ABS: Elf64Word = 0xfff1;

    /// Represents an extended section index
    pub const SHN_XINDEX: Elf64Word = 0xffff;

    /// Represents a null section type
    pub const SHT_NULL: Elf64Word = 0;

    /// Represents a string table section type
    pub const SHT_STRTAB: Elf64Word = 3;

    /// Represents a section with no associated data in the ELF file
    pub const SHT_NOBITS: Elf64Word = 8;

    /// Reads a section header from a byte buffer and returns an [`Elf64Shdr`] instance.
    ///
    /// # Arguments
    ///
    /// * `shdr_buf` - A byte buffer containing the section header data.
    ///
    /// # Returns
    ///
    /// An [`Elf64Shdr`] instance representing the section header.
    pub fn read(shdr_buf: &'_ [u8]) -> Self {
        let sh_name = Elf64Word::from_le_bytes(shdr_buf[0..4].try_into().unwrap());
        let sh_type = Elf64Word::from_le_bytes(shdr_buf[4..8].try_into().unwrap());
        let sh_flags = Elf64Xword::from_le_bytes(shdr_buf[8..16].try_into().unwrap());
        let sh_addr = Elf64Addr::from_le_bytes(shdr_buf[16..24].try_into().unwrap());
        let sh_offset = Elf64Off::from_le_bytes(shdr_buf[24..32].try_into().unwrap());
        let sh_size = Elf64Xword::from_le_bytes(shdr_buf[32..40].try_into().unwrap());
        let sh_link = Elf64Word::from_le_bytes(shdr_buf[40..44].try_into().unwrap());
        let sh_info = Elf64Word::from_le_bytes(shdr_buf[44..48].try_into().unwrap());
        let sh_addralign = Elf64Xword::from_le_bytes(shdr_buf[48..56].try_into().unwrap());
        let sh_entsize = Elf64Xword::from_le_bytes(shdr_buf[56..64].try_into().unwrap());

        let sh_flags = Elf64ShdrFlags::from_bits_truncate(sh_flags);

        Self {
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        }
    }

    /// Verifies the integrity of the ELF section header.
    ///
    /// # Errors
    /// Returns an [`Err`] variant of [`ElfError`] if validation fails.
    ///
    /// - If `sh_type` is `SHT_NULL`, the section is considered valid.
    /// - For non-empty sections (`SHT_NOBITS`), it checks the file range.
    /// - For allocated sections (`ALLOC` flag), it checks the address range and alignment.
    /// - Returns [`Ok`] if all checks pass.
    pub fn verify(&self) -> Result<(), ElfError> {
        if self.sh_type == Self::SHT_NULL {
            return Ok(());
        }

        if self.sh_type != Self::SHT_NOBITS {
            Elf64FileRange::try_from((self.sh_offset, self.sh_size))?;
        } else {
            Elf64FileRange::try_from((self.sh_offset, 0))?;
        }

        if self.sh_flags.contains(Elf64ShdrFlags::ALLOC) {
            Elf64AddrRange::try_from((self.sh_addr, self.sh_size))?;

            if self.sh_addralign != 0 {
                if self.sh_addralign != 0 && !self.sh_addralign.is_power_of_two() {
                    return Err(ElfError::InvalidAddressAlignment);
                }
                if self.sh_addr & (self.sh_addralign - 1) != 0 {
                    return Err(ElfError::InvalidAddressAlignment);
                }
            }
        } else if self.sh_addr != 0 {
            return Err(ElfError::InvalidAddressRange);
        }

        Ok(())
    }

    /// Returns the file range of the ELF section.
    ///
    /// If the section is not empty (`SHT_NOBITS`), it represents a valid file range
    /// based on the `sh_offset`and `sh_size`fields.
    ///
    /// # Returns
    /// Returns an [`Elf64FileRange`] representing the file range of the section.
    pub fn file_range(&self) -> Elf64FileRange {
        if self.sh_type != Self::SHT_NOBITS {
            Elf64FileRange::try_from((self.sh_offset, self.sh_size)).unwrap()
        } else {
            Elf64FileRange::try_from((self.sh_offset, 0)).unwrap()
        }
    }
}

/// Represents an iterator over section headers in an ELF64 file
#[derive(Debug)]
pub struct Elf64ShdrIterator<'a> {
    /// The ELF64 file from which section headers are being iterated
    elf_file: &'a Elf64File<'a>,
    /// Next index to be retrieved
    next: Elf64Word,
}

impl<'a> Elf64ShdrIterator<'a> {
    /// Creates a new [`Elf64ShdrIterator`] instance for iterating section headers
    /// in an ELF64 file.
    ///
    /// # Arguments
    ///
    /// - `elf_file`: The ELF64 file to iterate section headers from.
    ///
    /// # Returns
    ///
    /// - [`Self`]: A [`Self`] instance for iterating section headers.
    pub fn new(elf_file: &'a Elf64File<'a>) -> Self {
        Self { elf_file, next: 0 }
    }
}

impl Iterator for Elf64ShdrIterator<'_> {
    type Item = Elf64Shdr;

    /// Retrieves the next section header from the ELF64 file.
    ///
    /// # Returns
    ///
    /// - [`Option<Self::Item>`]: An option containing the next [`Elf64Shdr`] if available, or [`None`]
    ///   if all section headers have been iterated.
    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        if cur == self.elf_file.elf_hdr.e_shnum {
            return None;
        }
        self.next += 1;
        Some(self.elf_file.read_shdr(cur))
    }
}
