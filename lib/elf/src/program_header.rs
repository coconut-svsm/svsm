// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::Elf64AddrRange;
use super::Elf64FileRange;
use super::ElfError;
use bitflags::bitflags;

bitflags! {
/// Attributes of an ELF64 program header, to specify whether
/// the segment is readable, writable, and/or executable
    #[derive(Debug)]
    pub struct Elf64PhdrFlags : Elf64Word {
        const EXECUTE = 0x01;
        const WRITE   = 0x02;
        const READ    = 0x04;
    }
}

/// Program header entry in an ELF64 file
#[derive(Debug)]
pub struct Elf64Phdr {
    /// Type of the program header entry
    pub p_type: Elf64Word,
    /// Flags specifying the attributes of the segment
    pub p_flags: Elf64PhdrFlags,
    /// Offset in the ELF file where the segment data begins
    pub p_offset: Elf64Off,
    /// Virtual address at which the segment should be loaded into memory
    pub p_vaddr: Elf64Addr,
    /// Physical address at which the segment should be loaded (for systems with separate physical memory)
    pub p_paddr: Elf64Addr,
    /// Size of the segment in the ELF file (may be smaller than `p_memsz`)
    pub p_filesz: Elf64Xword,
    /// Size of the segment in memory (may include additional padding)
    pub p_memsz: Elf64Xword,
    /// Alignment of the segment in memory and in the file
    pub p_align: Elf64Xword,
}

impl Elf64Phdr {
    /// Represents a null program header type
    pub const PT_NULL: Elf64Word = 0;
    /// Represents a loadable segment program header type
    pub const PT_LOAD: Elf64Word = 1;
    /// Represents a dynamic segment program header type
    pub const PT_DYNAMIC: Elf64Word = 2;
    /// Represents a interpreter program header type
    pub const PT_INTERP: Elf64Word = 3;
    /// Represents a Note program header type
    pub const PT_NOTE: Elf64Word = 4;
    /// Represents a Shared Library program header type
    pub const PT_SHLIB: Elf64Word = 5;
    /// Represents the Program Header Table itself
    pub const PT_PHDR: Elf64Word = 6;
    /// Processor-specific entries lower bound
    pub const PT_LOPROC: Elf64Word = 0x70000000;
    /// Processor-specific entries upper bound
    pub const PT_HIPROC: Elf64Word = 0x7fffffff;

    /// Reads a program header from a byte buffer and returns an [`Elf64Phdr`] instance.
    ///
    /// # Arguments
    ///
    /// * `phdr_buf` - A byte buffer containing the program header data.
    ///
    /// # Returns
    ///
    /// An [`Elf64Phdr`] instance representing the program header.
    pub fn read(phdr_buf: &[u8]) -> Self {
        let p_type = Elf64Word::from_le_bytes(phdr_buf[0..4].try_into().unwrap());
        let p_flags = Elf64Word::from_le_bytes(phdr_buf[4..8].try_into().unwrap());
        let p_offset = Elf64Off::from_le_bytes(phdr_buf[8..16].try_into().unwrap());
        let p_vaddr = Elf64Addr::from_le_bytes(phdr_buf[16..24].try_into().unwrap());
        let p_paddr = Elf64Addr::from_le_bytes(phdr_buf[24..32].try_into().unwrap());
        let p_filesz = Elf64Xword::from_le_bytes(phdr_buf[32..40].try_into().unwrap());
        let p_memsz = Elf64Xword::from_le_bytes(phdr_buf[40..48].try_into().unwrap());
        let p_align = Elf64Xword::from_le_bytes(phdr_buf[48..56].try_into().unwrap());

        let p_flags = Elf64PhdrFlags::from_bits_truncate(p_flags);

        Self {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
        }
    }

    /// Verifies the integrity and validity of the program header.
    ///
    /// # Returns
    ///
    /// Returns [`Ok`] if the program header is valid; otherwise, an [`Err`]
    /// variant with an [`ElfError`] is returned.
    pub fn verify(&self) -> Result<(), ElfError> {
        if self.p_type == Self::PT_NULL {
            return Ok(());
        }

        if self.p_type == Self::PT_LOAD && self.p_memsz < self.p_filesz {
            return Err(ElfError::InvalidSegmentSize);
        }

        if self.p_align > 1 {
            if !self.p_align.is_power_of_two() {
                return Err(ElfError::InvalidAddressAlignment);
            }

            if self.p_vaddr % self.p_align != self.p_offset % self.p_align {
                return Err(ElfError::UnalignedSegmentAddress);
            }
        }

        if self.p_filesz != 0 {
            Elf64FileRange::try_from((self.p_offset, self.p_filesz))?;
        }
        if self.p_memsz != 0 {
            Elf64AddrRange::try_from((self.p_vaddr, self.p_memsz))?;
        }

        Ok(())
    }

    /// Returns the file range of the segment as an [`Elf64FileRange`].
    ///
    /// # Returns
    ///
    /// An [`Elf64FileRange`] representing the file range of the segment.
    pub fn file_range(&self) -> Elf64FileRange {
        Elf64FileRange::try_from((self.p_offset, self.p_filesz)).unwrap()
    }

    /// Returns the virtual address range of the segment as an [`Elf64AddrRange`].
    ///
    /// # Returns
    ///
    /// An [`Elf64AddrRange`] representing the virtual address range of the segment.
    pub fn vaddr_range(&self) -> Elf64AddrRange {
        Elf64AddrRange::try_from((self.p_vaddr, self.p_memsz)).unwrap()
    }
}
