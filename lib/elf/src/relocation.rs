// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::{Elf64AddrRange, Elf64LoadSegments, Elf64Shdr, Elf64Symtab, ElfError};

/// Represents a relocation entry in an ELF64 file ([`Elf64Rela`])
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    /// Offset within the section where the relocation should be applied
    r_offset: Elf64Addr,
    /// A combination of symbol index and relocation type information
    r_info: Elf64Xword,
    /// The value to add to the target symbol's value during relocation
    r_addend: Elf64Sxword,
}

impl Elf64Rela {
    /// Extracts the symbol index from the `r_info` field
    fn get_sym(&self) -> Elf64Word {
        (self.r_info >> 32) as Elf64Word
    }

    /// Extracts the relocation type from the `r_info` field
    fn get_type(&self) -> Elf64Word {
        (self.r_info & 0xffffffffu64) as Elf64Word
    }

    /// Reads an [`Elf64Rela`] relocation entry from the provided buffer.
    ///
    /// # Arguments
    ///
    /// - `rela_buf`: A slice of bytes containing the relocation entry data.
    ///
    /// # Returns
    ///
    /// - [`Elf64Rela`]: An [`Elf64Rela`] instance parsed from the buffer.
    fn read(rela_buf: &[u8]) -> Self {
        let r_offset = Elf64Addr::from_le_bytes(rela_buf[0..8].try_into().unwrap());
        let r_info = Elf64Xword::from_le_bytes(rela_buf[8..16].try_into().unwrap());
        let r_addend = Elf64Sxword::from_le_bytes(rela_buf[16..24].try_into().unwrap());
        Self {
            r_offset,
            r_info,
            r_addend,
        }
    }
}

/// Represents a collection of relocation entries in an ELF64 file ([`Elf64Relas`])
#[derive(Debug)]
pub struct Elf64Relas<'a> {
    /// The underlying buffer containing the relocation entries
    relas_buf: &'a [u8],
    /// Size of each relocation entry in bytes
    entsize: usize,
    /// Number of relocation entries in the collection
    relas_num: usize,
}

impl<'a> Elf64Relas<'a> {
    /// Creates a new [`Elf64Relas`] instance from the provided buffer and entry size.
    ///
    /// # Arguments
    ///
    /// - `relas_buf`: The buffer containing the relocation entries.
    /// - `entsize`: The size of each relocation entry in bytes.
    ///
    /// # Returns
    ///
    /// - [`Result<Self, ElfError>`]: A [`Result`] containing the [`Elf64Relas`] instance if valid,
    ///   or an [`ElfError`] if the provided parameters are invalid.
    pub fn new(relas_buf: &'a [u8], entsize: Elf64Xword) -> Result<Self, ElfError> {
        let entsize = usize::try_from(entsize).map_err(|_| ElfError::InvalidRelocationEntrySize)?;
        if entsize < 24 {
            return Err(ElfError::InvalidRelocationEntrySize);
        }
        let relas_num = relas_buf.len() / entsize;
        Ok(Self {
            relas_buf,
            entsize,
            relas_num,
        })
    }

    /// Reads a relocation entry from the collection by its index.
    ///
    /// # Arguments
    ///
    /// - `i`: The index of the relocation entry to retrieve.
    ///
    /// # Returns
    ///
    /// - [`Result<Elf64Rela, ElfError>`]: A [`Result`] containing the [`Elf64Rela`] entry if found,
    ///   or an [`ElfError`] if the index is out of bounds or the entry is invalid.
    pub fn read_rela(&self, i: usize) -> Result<Elf64Rela, ElfError> {
        let rela_off = i * self.entsize;
        let rela_buf = &self.relas_buf[rela_off..(rela_off + self.entsize)];
        Ok(Elf64Rela::read(rela_buf))
    }
}

/// Represents a relocation operation
#[derive(Debug, Clone, Copy)]
pub struct Elf64RelocOp {
    /// Destination address where the relocation operation should be applied
    pub dst: Elf64Addr,
    /// The value to be written to the destination address
    pub value: [u8; 8],
    /// The length (in bytes) of the value to be written
    pub value_len: usize,
}

/// A trait for processing ELF64 relocations
pub trait Elf64RelocProcessor {
    /// Applies a relocation operation to produce an [`Elf64RelocOp`].
    ///
    /// # Arguments
    ///
    /// - `rela`: The relocation entry specifying the operation.
    /// - `load_base`: The base address for loading ELF sections.
    /// - `sym_value`: The value associated with the symbol being relocated.
    ///
    /// # Returns
    ///
    /// - [`Result<Elf64RelocOp, ElfError>`]: A [`Result`] containing the
    ///   relocation operation ([`Elf64RelocOp`]) if successful, or an [`ElfError`] if
    ///   there was an issue applying the relocation.
    fn apply_relocation(
        &self,
        rela: &Elf64Rela,
        load_base: Elf64Xword,
        sym_value: Elf64Addr,
    ) -> Result<Elf64RelocOp, ElfError>;
}

/// Relocation processor specifically for x86_64 ELF files.
#[derive(Clone, Copy, Debug)]
pub struct Elf64X86RelocProcessor;

impl Elf64X86RelocProcessor {
    /// Relocation type value for a 64-bit absolute relocation
    const R_X86_64_64: Elf64Word = 1;
    /// Relocation type value for a PC-relative 32-bit relocation
    const R_X86_64_PC32: Elf64Word = 2;
    /// Relocation type value for a relative relocation
    const R_X86_64_RELATIVE: Elf64Word = 8;
    /// Relocation type value for a 32-bit relocation
    const R_X86_64_32: Elf64Word = 10;
    /// Relocation type value for a signed 32-bit relocation
    const R_X86_64_32S: Elf64Word = 11;
    /// Relocation type value for a PC-relative 64-bit relocation
    const R_X86_64_PC64: Elf64Word = 24;

    /// Creates a new [`Elf64X86RelocProcessor`] instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Elf64X86RelocProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl Elf64RelocProcessor for Elf64X86RelocProcessor {
    /// Applies a relocation operation for x86_64 ELF files.
    ///
    /// # Arguments
    ///
    /// - `rela`: The relocation entry specifying the operation.
    /// - `load_base`: The base address for loading ELF sections.
    /// - `sym_value`: The value associated with the symbol being relocated.
    ///
    /// # Returns
    ///
    /// - [`Result<Elf64RelocOp, ElfError>`]: A [`Result`] containing the relocation
    ///   operation ([`Elf64RelocOp`]) if successful, or an [`ElfError`] if there was an
    ///   issue applying the relocation.
    fn apply_relocation(
        &self,
        rela: &Elf64Rela,
        load_base: Elf64Xword,
        sym_value: Elf64Addr,
    ) -> Result<Elf64RelocOp, ElfError> {
        // load_base is the difference between the actual mapping addresses
        // and the ELF vaddrs. This signed difference is represented in
        // two's complement.
        let p = rela.r_offset.wrapping_add(load_base);
        // Use two's complement arithmethic for the addend.
        let a = rela.r_addend as u64;
        let (value, value_len) = match rela.get_type() {
            Self::R_X86_64_64 => {
                let value = sym_value.wrapping_add(a);
                (value, 8)
            }
            Self::R_X86_64_PC32 => {
                let value = sym_value.wrapping_add(a);
                let value = value.wrapping_sub(p);
                (value, 4)
            }
            Self::R_X86_64_RELATIVE => {
                let value = load_base.wrapping_add(a);
                (value, 8)
            }
            Self::R_X86_64_32 => {
                let value = sym_value.wrapping_add(a);
                (value, 4)
            }
            Self::R_X86_64_32S => {
                let value = sym_value.wrapping_add(a);
                (value, 4)
            }
            Self::R_X86_64_PC64 => {
                let value = sym_value.wrapping_add(a);
                let value = value.wrapping_sub(p);
                (value, 8)
            }
            _ => return Err(ElfError::UnrecognizedRelocationType),
        };

        let value = value.to_le_bytes();
        Ok(Elf64RelocOp {
            dst: p,
            value,
            value_len,
        })
    }
}

/// An iterator that applies relocation operations to ELF64 relocations
#[derive(Debug)]
pub struct Elf64AppliedRelaIterator<'a, RP: Elf64RelocProcessor> {
    /// The ELF64 relocation processor used for applying relocations
    rela_proc: RP,
    /// Base address for loading ELF sections
    load_base: Elf64Xword,
    /// Reference to the ELF64 load segments
    load_segments: &'a Elf64LoadSegments,
    /// ELF64 relocation entries
    relas: Elf64Relas<'a>,
    /// Optional symbol table for resolving symbols
    symtab: Option<Elf64Symtab<'a>>,
    /// Index of the next relocation entry to process
    next: usize,
}

impl<'a, RP: Elf64RelocProcessor> Elf64AppliedRelaIterator<'a, RP> {
    /// Creates a new [`Elf64AppliedRelaIterator`] instance.
    ///
    /// # Arguments
    ///
    /// - `rela_proc`: The ELF64 relocation processor.
    /// - `load_base`: The base address for loading ELF sections.
    /// - `load_segments`: Reference to the ELF64 load segments.
    /// - `relas`: ELF64 relocation entries.
    /// - `symtab`: Optional symbol table for symbol resolution.
    ///
    /// # Returns
    ///
    /// - A new [`Elf64AppliedRelaIterator`] instance.
    pub fn new(
        rela_proc: RP,
        load_base: Elf64Xword,
        load_segments: &'a Elf64LoadSegments,
        relas: Elf64Relas<'a>,
        symtab: Option<Elf64Symtab<'a>>,
    ) -> Self {
        Self {
            rela_proc,
            load_base,
            load_segments,
            relas,
            symtab,
            next: 0,
        }
    }
}

impl<RP: Elf64RelocProcessor> Iterator for Elf64AppliedRelaIterator<'_, RP> {
    type Item = Result<Option<Elf64RelocOp>, ElfError>;

    /// Advances the iterator to the next relocation operation, processes it,
    /// and returns the result.
    ///
    /// If there are no more relocations to process, [`None`] is returned to signal
    /// the end of the iterator.
    ///
    /// # Returns
    ///
    /// - [`Some<Ok<None>>`]: If the relocation entry indicates no operation (type == 0).
    /// - [`Some<Ok<Some<reloc_op>>>`]: If a relocation operation is successfully applied.
    /// - [`Some<Err<ElfError>>`]: If an error occurs during relocation processing.
    /// - [`None`]: If there are no more relocation entries to process.
    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        if cur == self.relas.relas_num {
            return None;
        }
        self.next += 1;

        // Read the next ELF64 relocation entry
        let rela = match self.relas.read_rela(cur) {
            Ok(rela) => rela,
            Err(e) => return Some(Err(e)),
        };

        // Check if the relocation type is zero, indicating no operation
        if rela.get_type() == 0 {
            return Some(Ok(None));
        }

        // Resolve the symbol associated with the relocation
        let sym_index = rela.get_sym();
        let sym_value = if sym_index != Elf64Symtab::STN_UNDEF {
            let symtab = match &self.symtab {
                Some(symtab) => symtab,
                None => return Some(Err(ElfError::InvalidSymbolIndex)),
            };
            let sym = match symtab.read_sym(sym_index) {
                Ok(sym) => sym,
                Err(e) => return Some(Err(e)),
            };

            if sym.st_shndx as Elf64Word == Elf64Shdr::SHN_UNDEF {
                return Some(Err(ElfError::RelocationAgainstUndefSymbol));
            } else if sym.st_shndx as Elf64Word == Elf64Shdr::SHN_ABS {
                // Absolute symbol, no adjustment by load_base.
                sym.st_value
            } else {
                // load_base is the difference between the actual mapping
                // addresses and the ELF vaddrs. This signed difference is
                // represented in two's complement.
                sym.st_value.wrapping_add(self.load_base)
            }
        } else {
            0
        };

        // Apply the relocation and obtain the relocation operation
        let reloc_op = match self
            .rela_proc
            .apply_relocation(&rela, self.load_base, sym_value)
        {
            Ok(reloc_op) => reloc_op,
            Err(e) => return Some(Err(e)),
        };

        // Check that the write destination is contained within one of the
        // PT_LOAD segments, so that the consumer won't write the result into
        // nowhere.
        let dst_vaddr_begin = rela.r_offset;
        let dst_vaddr_end = match dst_vaddr_begin.checked_add(reloc_op.value_len as Elf64Xword) {
            Some(dst_end) => dst_end,
            None => return Some(Err(ElfError::InvalidAddressRange)),
        };
        let dst_vaddr_range = Elf64AddrRange {
            vaddr_begin: dst_vaddr_begin,
            vaddr_end: dst_vaddr_end,
        };
        if self
            .load_segments
            .lookup_vaddr_range(&dst_vaddr_range)
            .is_none()
        {
            return Some(Err(ElfError::InvalidRelocationOffset));
        }

        Some(Ok(Some(reloc_op)))
    }
}
