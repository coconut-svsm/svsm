// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::ElfError;
use core::mem;

/// Header of the ELF64 file, including fields describing properties such
/// as type, machine architecture, entry point, etc.

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Elf64Hdr {
    /// An array of 16 bytes representing the ELF identification, including the ELF magic number
    pub e_ident: [Elf64char; 16],
    /// The type of ELF file
    pub e_type: Elf64Half,
    /// The target architecture of the ELF file
    pub e_machine: Elf64Half,
    /// The version of the ELF file
    pub e_version: Elf64Word,
    /// The virtual address of the program entry point
    pub e_entry: Elf64Addr,
    /// The file offset to the start of the program header table
    pub e_phoff: Elf64Off,
    /// The file offset to the start of the program header table
    pub e_shoff: Elf64Off,
    /// The file offset to the start of the section header table
    /// Processor-specific flags associated with the file
    pub e_flags: Elf64Word,
    /// The size of the ELF header
    pub e_ehsize: Elf64Half,
    /// The size of a program header entry
    pub e_phentsize: Elf64Half,
    /// The number of program header entries
    pub e_phnum: Elf64Half,
    /// The size of a section header entry
    pub e_shentsize: Elf64Half,
    /// The number of section header entries (overflowed to a Word-sized entry when needed)
    pub e_shnum: Elf64Word, // The actual Elf64Hdr entry is Elf64Half, on overflow it's read from section
    // table entry zero
    /// The section header table index of the section name string table
    pub e_shstrndx: Elf64Word, // The actual Elf64Hdr entry is Elf64Half, on overflow it's read from section
                               // table entry zero
}

impl Elf64Hdr {
    const EI_MAG0: usize = 0;
    const EI_CLASS: usize = 4;
    const EI_DATA: usize = 5;
    const EI_VERSION: usize = 6;
    const EI_OSABI: usize = 7;

    const ELFMAG: [Elf64char; 4] = [0x7f, b'E', b'L', b'F'];

    const ELFCLASS64: Elf64char = 2;

    const ELFDATA2LSB: Elf64char = 1;

    const ELFOSABI_NONE: Elf64char = 0;
    const ELFOSABI_GNU: Elf64char = 3;

    const ET_EXEC: Elf64Half = 2;

    const EM_X86_64: Elf64Half = 62;

    const EV_CURRENT: Elf64Word = 1;

    /// Reads an ELF64 header from a byte buffer.
    ///
    /// This function reads an ELF64 header from the provided byte buffer and performs various
    /// checks to verify the integrity and compatibility of the ELF file. If any errors are
    /// encountered during the reading process, they are returned as an [`ElfError`].
    ///
    /// # Parameters
    ///
    /// - `buf`: A byte slice containing the ELF header data.
    ///
    /// # Returns
    ///
    /// - [`Result<Self, ElfError>`]: A result containing the parsed [`Elf64Hdr`] if successful,
    ///   or an [`ElfError`] if any errors occur during parsing.
    ///
    /// # Errors
    ///
    /// This function may return the following errors:
    ///
    /// - [`ElfError::FileTooShort`]: The provided buffer is too short to contain a valid ELF header.
    /// - [`ElfError::UnrecognizedMagic`]: The ELF magic number in the identification section is unrecognized.
    /// - [`ElfError::UnsupportedClass`]: The ELF file class (64-bit) is not supported.
    /// - [`ElfError::UnsupportedEndianess`]: The endianness of the ELF file is not supported.
    /// - [`ElfError::UnsupportedVersion`]: The version of the ELF file is not supported.
    /// - [`ElfError::UnsupportedOsAbi`]: The ELF file uses an unsupported OS/ABI.
    /// - Other errors specific to reading and parsing the header fields.
    pub fn read(buf: &[u8]) -> Result<Self, ElfError> {
        // Examine the e_ident[] magic.
        if buf.len() < 16 {
            return Err(ElfError::FileTooShort);
        }
        let e_ident: [Elf64char; 16] = buf[..16].try_into().unwrap();
        if e_ident[Self::EI_MAG0..(Self::EI_MAG0 + mem::size_of_val(&Self::ELFMAG))] != Self::ELFMAG
        {
            return Err(ElfError::UnrecognizedMagic);
        } else if e_ident[Self::EI_CLASS] != Self::ELFCLASS64 {
            return Err(ElfError::UnsupportedClass);
        } else if e_ident[Self::EI_DATA] != Self::ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndianess);
        } else if e_ident[Self::EI_VERSION] != Self::EV_CURRENT as Elf64char {
            return Err(ElfError::UnsupportedVersion);
        } else if e_ident[Self::EI_OSABI] != Self::ELFOSABI_NONE
            && e_ident[Self::EI_OSABI] != Self::ELFOSABI_GNU
        {
            return Err(ElfError::UnsupportedOsAbi);
        }

        // ELF file is confirmed to be of ELFCLASS64, so the total header size
        // should equal 64 bytes.
        if buf.len() < 64 {
            return Err(ElfError::FileTooShort);
        }
        let e_type = Elf64Half::from_le_bytes(buf[16..18].try_into().unwrap());
        let e_machine = Elf64Half::from_le_bytes(buf[18..20].try_into().unwrap());
        let e_version = Elf64Word::from_le_bytes(buf[20..24].try_into().unwrap());
        let e_entry = Elf64Addr::from_le_bytes(buf[24..32].try_into().unwrap());
        let e_phoff = Elf64Off::from_le_bytes(buf[32..40].try_into().unwrap());
        let e_shoff = Elf64Off::from_le_bytes(buf[40..48].try_into().unwrap());
        let e_flags = Elf64Word::from_le_bytes(buf[48..52].try_into().unwrap());
        let e_ehsize = Elf64Half::from_le_bytes(buf[52..54].try_into().unwrap());
        let e_phentsize = Elf64Half::from_le_bytes(buf[54..56].try_into().unwrap());
        let e_phnum = Elf64Half::from_le_bytes(buf[56..58].try_into().unwrap());
        let e_shentsize = Elf64Half::from_le_bytes(buf[58..60].try_into().unwrap());
        let e_shnum = Elf64Half::from_le_bytes(buf[60..62].try_into().unwrap()) as Elf64Word;
        let e_shstrndx = Elf64Half::from_le_bytes(buf[62..64].try_into().unwrap()) as Elf64Word;

        if e_type != Self::ET_EXEC {
            return Err(ElfError::UnsupportedType);
        }
        if e_machine != Self::EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }
        if e_version != Self::EV_CURRENT {
            return Err(ElfError::UnsupportedVersion);
        }

        Ok(Self {
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }
}
