// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

/// Errors while working with ELF files, e.g. invalid, unmaped or unbacked
/// address ranges, invalid ELF type or endianness. The [`fmt::Display`] trait
/// is implemented to allow formatting error instances.
///
/// # Examples
///
/// To format an [`ElfError`] as a string, you can use the `to_string()`method
/// or the `format!` macro, like this:
///
/// ```rust
/// use elf::ElfError;
///
/// let error = ElfError::InvalidAddressRange;
/// let error_message = error.to_string();
///
/// assert_eq!(error_message, "invalid ELF address range");
/// ```
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ElfError {
    FileTooShort,

    InvalidAddressRange,
    InvalidAddressAlignment,
    InvalidFileRange,
    UnmappedVaddrRange,
    UnbackedVaddrRange,

    UnrecognizedMagic,
    UnsupportedClass,
    UnsupportedEndianess,
    UnsupportedOsAbi,
    UnsupportedType,
    UnsupportedMachine,
    UnsupportedVersion,
    InvalidPhdrSize,
    InvalidShdrSize,

    InvalidSegmentSize,
    UnalignedSegmentAddress,
    LoadSegmentConflict,
    DynamicPhdrConflict,

    UnterminatedDynamicSection,
    DynamicFieldConflict,
    UnrecognizedDynamicField,
    MissingDynamicField,

    InvalidSectionIndex,
    IncompatibleSectionType,

    InvalidStrtabString,

    InvalidSymbolEntrySize,
    InvalidSymbolIndex,

    InvalidRelocationEntrySize,
    UnrecognizedRelocationType,
    InvalidRelocationOffset,
    RelocationAgainstUndefSymbol,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooShort => {
                write!(f, "ELF file too short")
            }

            Self::InvalidAddressRange => {
                write!(f, "invalid ELF address range")
            }
            Self::InvalidAddressAlignment => {
                write!(f, "invalid ELF address alignment")
            }
            Self::InvalidFileRange => {
                write!(f, "invalid ELF file range")
            }
            Self::UnmappedVaddrRange => {
                write!(f, "reference to unmapped ELF address range")
            }
            Self::UnbackedVaddrRange => {
                write!(f, "reference ELF address range not backed by file")
            }

            Self::UnrecognizedMagic => {
                write!(f, "unrecognized ELF magic")
            }
            Self::UnsupportedClass => {
                write!(f, "unsupported ELF class")
            }
            Self::UnsupportedEndianess => {
                write!(f, "unsupported ELF endianess")
            }
            Self::UnsupportedOsAbi => {
                write!(f, "unsupported ELF ABI")
            }
            Self::UnsupportedType => {
                write!(f, "unsupported ELF file type")
            }
            Self::UnsupportedMachine => {
                write!(f, "unsupported ELF machine")
            }
            Self::UnsupportedVersion => {
                write!(f, "unsupported ELF version")
            }
            Self::InvalidPhdrSize => {
                write!(f, "invalid ELF program header size")
            }
            Self::InvalidShdrSize => {
                write!(f, "invalid ELF section header size")
            }

            Self::InvalidSegmentSize => {
                write!(f, "invalid ELF segment size")
            }
            Self::UnalignedSegmentAddress => {
                write!(f, "unaligned ELF segment address")
            }
            Self::LoadSegmentConflict => {
                write!(f, "ELF PT_LOAD segment conflict")
            }
            Self::DynamicPhdrConflict => {
                write!(f, "multiple ELF PT_DYNAMIC program headers")
            }

            Self::UnterminatedDynamicSection => {
                write!(f, "unterminated ELF dynamic section")
            }
            Self::DynamicFieldConflict => {
                write!(f, "conflicting fields in ELF dynamic section")
            }
            Self::UnrecognizedDynamicField => {
                write!(f, "unrecognized field in ELF dynamic section")
            }
            Self::MissingDynamicField => {
                write!(f, "missing field in ELF dynamic section")
            }

            Self::InvalidSectionIndex => {
                write!(f, "invalid ELF section index")
            }
            Self::IncompatibleSectionType => {
                write!(f, "unexpected ELF section type")
            }

            Self::InvalidStrtabString => {
                write!(f, "invalid ELF strtab string")
            }

            Self::InvalidSymbolEntrySize => {
                write!(f, "invalid ELF symbol entry size")
            }
            Self::InvalidSymbolIndex => {
                write!(f, "invalid ELF symbol index")
            }

            Self::InvalidRelocationEntrySize => {
                write!(f, "invalid ELF relocation entry size")
            }
            Self::UnrecognizedRelocationType => {
                write!(f, "unrecognized ELF relocation type")
            }
            Self::InvalidRelocationOffset => {
                write!(f, "ELF relocation offset out of bounds")
            }
            Self::RelocationAgainstUndefSymbol => {
                write!(f, "ELF relocation against undefined symbol")
            }
        }
    }
}
