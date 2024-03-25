// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::ElfError;

/// This struct represents a parsed 64-bit ELF file. It contains information
/// about the ELF file's header, load segments, dynamic section, and more.

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Elf64FileRange {
    pub offset_begin: usize,
    pub offset_end: usize,
}

impl TryFrom<(Elf64Off, Elf64Xword)> for Elf64FileRange {
    type Error = ElfError;

    /// Tries to create an [`Elf64FileRange`] from a tuple of [`(Elf64Off, Elf64Xword)`].
    ///
    ///
    /// # Errors
    ///
    /// Returns an [`ElfError::InvalidFileRange`] if the calculation of `offset_end`
    /// results in an invalid file range.
    fn try_from(value: (Elf64Off, Elf64Xword)) -> Result<Self, Self::Error> {
        let offset_begin = usize::try_from(value.0).map_err(|_| ElfError::InvalidFileRange)?;
        let size = usize::try_from(value.1).map_err(|_| ElfError::InvalidFileRange)?;
        let offset_end = offset_begin
            .checked_add(size)
            .ok_or(ElfError::InvalidFileRange)?;
        Ok(Self {
            offset_begin,
            offset_end,
        })
    }
}
