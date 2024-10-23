// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::ElfError;

use core::ffi;

/// Represents an ELF64 string table ([`Elf64Strtab`]) containing strings
/// used within the ELF file
#[derive(Debug, Default, PartialEq)]
pub struct Elf64Strtab<'a> {
    strtab_buf: &'a [u8],
}

impl<'a> Elf64Strtab<'a> {
    /// Creates a new [`Elf64Strtab`] instance from the provided string table buffer
    pub fn new(strtab_buf: &'a [u8]) -> Self {
        Self { strtab_buf }
    }

    /// Retrieves a string from the string table by its index.
    ///
    /// # Arguments
    ///
    /// - `index`: The index of the string to retrieve.
    ///
    /// # Returns
    ///
    /// - [`Result<&'a ffi::CStr, ElfError>`]: A [`Result`] containing the string as a CStr reference
    ///   if found, or an [`ElfError`] if the index is out of bounds or the string is invalid.
    pub fn get_str(&self, index: Elf64Word) -> Result<&'a ffi::CStr, ElfError> {
        let index = usize::try_from(index).unwrap();
        if index >= self.strtab_buf.len() {
            return Err(ElfError::InvalidStrtabString);
        }

        ffi::CStr::from_bytes_until_nul(&self.strtab_buf[index..])
            .map_err(|_| ElfError::InvalidStrtabString)
    }
}

/// Represents an ELF64 symbol ([`Elf64Sym`]) within the symbol table.
#[derive(Debug, Copy, Clone)]
pub struct Elf64Sym {
    /// Name of the symbol as an index into the string table
    pub st_name: Elf64Word,
    /// Symbol information and binding attributes
    pub st_info: Elf64char,
    /// Reserved for additional symbol attributes (unused)
    pub st_other: Elf64char,
    /// Section index associated with the symbol
    pub st_shndx: Elf64Half,
    /// Value or address of the symbol
    pub st_value: Elf64Addr,
    /// Size of the symbol in bytes
    pub st_size: Elf64Xword,
}

impl Elf64Sym {
    /// Reads an [`Elf64Sym`] from the provided buffer.
    ///
    /// # Arguments
    ///
    /// - `buf`: A slice of bytes containing the symbol data.
    ///
    /// # Returns
    ///
    /// - [`Elf64Sym`]: An [`Elf64Sym`] instance parsed from the buffer.
    pub fn read(buf: &[u8]) -> Self {
        let st_name = Elf64Word::from_le_bytes(buf[0..4].try_into().unwrap());
        let st_info = Elf64char::from_le_bytes(buf[4..5].try_into().unwrap());
        let st_other = Elf64char::from_le_bytes(buf[5..6].try_into().unwrap());
        let st_shndx = Elf64Half::from_le_bytes(buf[6..8].try_into().unwrap());
        let st_value = Elf64Addr::from_le_bytes(buf[8..16].try_into().unwrap());
        let st_size = Elf64Xword::from_le_bytes(buf[16..24].try_into().unwrap());
        Self {
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size,
        }
    }
}

/// Represents an ELF64 symbol table ([`Elf64Symtab`]) containing
/// symbols used within the ELF file.
#[derive(Debug)]
pub struct Elf64Symtab<'a> {
    /// The underlying buffer containing the symbol table data
    syms_buf: &'a [u8],
    /// Size of each symbol entry in bytes
    entsize: usize,
    /// Number of symbols in the symbol table
    syms_num: Elf64Word,
}

impl<'a> Elf64Symtab<'a> {
    /// Indicates an undefined symbol
    pub const STN_UNDEF: Elf64Word = 0;

    /// Creates a new [`Elf64Symtab`] instance from the provided symbol table buffer.
    ///
    /// # Arguments
    ///
    /// - `syms_buf`: The buffer containing the symbol table data.
    /// - `entsize`: The size of each symbol entry in bytes.
    ///
    /// # Returns
    ///
    /// - [`Result<Self, ElfError>`]: A [`Result`] containing the [`Elf64Symtab`] instance if valid,
    ///   or an [`ElfError`] if the provided parameters are invalid.
    pub fn new(syms_buf: &'a [u8], entsize: Elf64Xword) -> Result<Self, ElfError> {
        let entsize = usize::try_from(entsize).map_err(|_| ElfError::InvalidSymbolEntrySize)?;
        if entsize < 24 {
            return Err(ElfError::InvalidSymbolEntrySize);
        }
        let syms_num = syms_buf.len() / entsize;
        let syms_num = Elf64Word::try_from(syms_num).map_err(|_| ElfError::InvalidSymbolIndex)?;
        Ok(Self {
            syms_buf,
            entsize,
            syms_num,
        })
    }

    /// Reads a symbol from the symbol table by its index.
    ///
    /// # Arguments
    ///
    /// - `i`: The index of the symbol to retrieve.
    ///
    /// # Returns
    ///
    /// - [`Result<Elf64Sym, ElfError>`]: A [`Result`] containing the [`Elf64Sym`] if found,
    ///   or an [`ElfError`] if the index is out of bounds or the symbol is invalid.
    pub fn read_sym(&self, i: Elf64Word) -> Result<Elf64Sym, ElfError> {
        if i > self.syms_num {
            return Err(ElfError::InvalidSymbolIndex);
        }
        let i = usize::try_from(i).map_err(|_| ElfError::InvalidSymbolIndex)?;
        let sym_off = i * self.entsize;
        let sym_buf = &self.syms_buf[sym_off..(sym_off + self.entsize)];
        Ok(Elf64Sym::read(sym_buf))
    }
}
