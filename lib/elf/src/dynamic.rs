// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::Elf64AddrRange;
use super::ElfError;

/// Represents an ELF64 dynamic relocation table
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Elf64DynamicRelocTable {
    /// Virtual address of the relocation table (DT_RELA / DR_REL)
    pub base_vaddr: Elf64Addr,
    /// Size of the relocation table (DT_RELASZ / DT_RELSZ)
    pub size: Elf64Xword,
    /// Size of each relocation entry (DT_RELAENT / DT_RELENT)
    pub entsize: Elf64Xword,
}

impl Elf64DynamicRelocTable {
    /// Verifies the integrity and validity of the dynamic relocation table.
    ///
    /// # Returns
    ///
    /// Returns [`Ok`] if the dynamic relocation table is valid; otherwise, returns an
    /// [`ElfError`] indicating the issue.
    pub fn verify(&self) -> Result<(), ElfError> {
        Elf64AddrRange::try_from((self.base_vaddr, self.size))?;
        Ok(())
    }

    /// Calculates and returns the virtual address range covered by the dynamic relocation table.
    ///
    /// # Returns
    ///
    /// An [`Elf64AddrRange`] representing the virtual address range of the dynamic relocation table.
    pub fn vaddr_range(&self) -> Elf64AddrRange {
        Elf64AddrRange::try_from((self.base_vaddr, self.size)).unwrap()
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Elf64DynamicSymtab {
    /// Base virtual address of the symbol table (DT_SYMTAB)
    pub base_vaddr: Elf64Addr,
    /// Size of each symbol table entry (DT_SYMENT)
    pub entsize: Elf64Xword,
    /// Optional value indicating the table index of symbols
    /// in the extended section header table (DT_SYMTAB_SHNDX)
    pub shndx: Option<Elf64Addr>,
}

impl Elf64DynamicSymtab {
    /// Verifies the integrity and validity of the dynamic symbol table.
    ///
    /// # Returns
    ///
    /// Returns [`Ok`] if the dynamic symbol table is valid; otherwise, returns an
    /// [`ElfError`] indicating the issue.
    fn verify(&self) -> Result<(), ElfError> {
        // Verification of the dynamic symbol table can be implemented here.
        // It may involve checking the table's base virtual address and the size of each entry.
        Ok(())
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Elf64Dynamic {
    // No DT_REL representation: "The AMD64 ABI architectures uses only
    // Elf64_Rela relocation entries [...]".
    /// Optional representation of the dynamic relocation table (DT_RELA / DT_REL)
    pub rela: Option<Elf64DynamicRelocTable>,
    /// Optional representation of the dynamic symbol table (DT_SYMTAB)
    pub symtab: Option<Elf64DynamicSymtab>,
    /// Flags related to dynamic linking (DT_FLAGS_1)
    pub flags_1: Elf64Xword,
}

impl Elf64Dynamic {
    /// Constant representing a null dynamic entry
    const DT_NULL: Elf64Xword = 0;
    /// Constant representing a hash table address (DT_HASH)
    const DT_HASH: Elf64Xword = 4;
    /// Constant representing the address of the string table (DT_STRTAB)
    const DT_STRTAB: Elf64Xword = 5;
    /// Constant representing the address of the symbol table (DT_SYMTAB)
    const DT_SYMTAB: Elf64Xword = 6;
    /// Constant representing the address of the relocation table (DT_RELA)
    const DT_RELA: Elf64Xword = 7;
    /// Constant representing the size of the relocation table (DT_RELASZ)
    const DT_RELASZ: Elf64Xword = 8;
    /// Constant representing the size of each relocation entry (DT_RELAENT)
    const DT_RELAENT: Elf64Xword = 9;
    /// Constant representing the size of the string table (DT_STRSZ)
    const DT_STRSZ: Elf64Xword = 10;
    /// Constant representing the size of each symbol table entry (DT_SYMENT)
    const DT_SYMENT: Elf64Xword = 11;
    /// Constant representing debug information (DT_DEBUG)
    const DT_DEBUG: Elf64Xword = 21;
    /// Constant representing the presence of text relocations (DT_TEXTREL)
    const DT_TEXTREL: Elf64Xword = 22;
    /// Constant representing dynamic flags (DT_FLAGS)
    const DT_FLAGS: Elf64Xword = 30;
    /// Constant representing the index of the symbol table section header (DT_SYMTAB_SHNDX)
    const DT_SYMTAB_SHNDX: Elf64Xword = 34;
    /// Constant representing GNU hash (DT_GNU_HASH)
    const DT_GNU_HASH: Elf64Xword = 0x6ffffef5;
    /// Constant representing the number of relocations (DT_RELACOUNT)
    const DT_RELACOUNT: Elf64Xword = 0x6ffffff9;
    /// Constant representing dynamic flags (DT_FLAGS_1)
    const DT_FLAGS_1: Elf64Xword = 0x6ffffffb;
    /// Constant representing position-independent executable flag (DF_PIE_1)
    const DF_PIE_1: Elf64Xword = 0x08000000;

    /// Reads the ELF64 dynamic section from a byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - A byte buffer containing the dynamic section data.
    ///
    /// # Returns
    ///
    /// Returns a [`Result`] containing the parsed [`Elf64Dynamic`] structure if successful, or an
    /// [`ElfError`] indicating the issue.
    pub fn read(buf: &[u8]) -> Result<Self, ElfError> {
        let mut rela: Option<Elf64Addr> = None;
        let mut relasz: Option<Elf64Xword> = None;
        let mut relaent: Option<Elf64Xword> = None;

        let mut symtab: Option<Elf64Addr> = None;
        let mut syment: Option<Elf64Xword> = None;
        let mut symtab_shndx: Option<Elf64Addr> = None;

        let mut flags_1: Option<Elf64Xword> = None;

        let mut fields = [
            (Self::DT_RELA, &mut rela),
            (Self::DT_RELASZ, &mut relasz),
            (Self::DT_RELAENT, &mut relaent),
            (Self::DT_SYMTAB, &mut symtab),
            (Self::DT_SYMENT, &mut syment),
            (Self::DT_SYMTAB_SHNDX, &mut symtab_shndx),
            (Self::DT_FLAGS_1, &mut flags_1),
        ];
        let ignored_fields = [
            Self::DT_HASH,
            Self::DT_STRTAB,
            Self::DT_STRSZ,
            Self::DT_DEBUG,
            Self::DT_TEXTREL,
            Self::DT_FLAGS,
            Self::DT_GNU_HASH,
            Self::DT_RELACOUNT,
        ];
        let mut null_seen = false;
        for entry_buf in buf.chunks(16) {
            let d_tag = Elf64Xword::from_le_bytes(entry_buf[0..8].try_into().unwrap());

            if d_tag == Self::DT_NULL {
                null_seen = true;
                break;
            }

            if let Some(field) = fields.iter_mut().find(|f| f.0 == d_tag) {
                if field.1.is_some() {
                    return Err(ElfError::DynamicFieldConflict);
                }

                let d_val = Elf64Xword::from_le_bytes(entry_buf[8..16].try_into().unwrap());
                *field.1 = Some(d_val);
            } else if ignored_fields.iter().all(|tag| *tag != d_tag) {
                // For unhandled fields not on the ignore list, bail out:
                // failing to take the associated, required fixup action from
                // the dynamic loader, if any, would result in a broken image,
                // respectively in hard to debug runtime breakages.
                return Err(ElfError::UnrecognizedDynamicField);
            }
        }
        if !null_seen {
            return Err(ElfError::UnterminatedDynamicSection);
        }

        let rela = if rela.is_some() || relasz.is_some() || relaent.is_some() {
            let rela = rela.ok_or(ElfError::MissingDynamicField)?;
            let relasz = relasz.ok_or(ElfError::MissingDynamicField)?;
            let relaent = relaent.ok_or(ElfError::MissingDynamicField)?;
            Some(Elf64DynamicRelocTable {
                base_vaddr: rela,
                size: relasz,
                entsize: relaent,
            })
        } else {
            None
        };

        let symtab = if symtab.is_some() || syment.is_some() {
            let symtab = symtab.ok_or(ElfError::MissingDynamicField)?;
            let syment = syment.ok_or(ElfError::MissingDynamicField)?;
            Some(Elf64DynamicSymtab {
                base_vaddr: symtab,
                entsize: syment,
                shndx: symtab_shndx,
            })
        } else {
            None
        };

        let flags_1 = flags_1.unwrap_or(0);

        Ok(Elf64Dynamic {
            rela,
            symtab,
            flags_1,
        })
    }

    /// Verifies the integrity and validity of the ELF64 dynamic section.
    ///
    /// # Returns
    ///
    /// Returns [`Ok`] if the dynamic section is valid; otherwise, returns an
    /// [`ElfError`] indicating the issue.
    pub fn verify(&self) -> Result<(), ElfError> {
        if let Some(rela) = &self.rela {
            rela.verify()?;
        }
        if let Some(symtab) = &self.symtab {
            symtab.verify()?;
        }
        Ok(())
    }

    /// Checks if the ELF64 executable is a Position-Independent Executable (PIE).
    ///
    /// # Returns
    ///
    /// Returns `true` if the PIE flag (DF_PIE_1) is set; otherwise, returns `false`.
    pub fn is_pie(&self) -> bool {
        self.flags_1 & Self::DF_PIE_1 != 0
    }
}
