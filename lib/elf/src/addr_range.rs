// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::ElfError;
use core::cmp;

/// Represents a 64-bit ELF virtual address range.
///
/// In mathematical notation, the range is [vaddr_begin, vaddr_end)
#[derive(PartialEq, Eq, Debug, Default, Clone, Copy)]
pub struct Elf64AddrRange {
    pub vaddr_begin: Elf64Addr,
    pub vaddr_end: Elf64Addr,
}

impl Elf64AddrRange {
    /// Returns the length of the virtual address range, calculated as the
    /// difference between `vaddr_end` and `vaddr_begin`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use elf::{Elf64Addr, Elf64AddrRange};
    ///
    /// let range = Elf64AddrRange {
    ///     vaddr_begin: 0x1000,
    ///     vaddr_end: 0x1100,
    /// };
    ///
    /// assert_eq!(range.len(), 0x100);
    /// ```
    pub fn len(&self) -> Elf64Xword {
        self.vaddr_end - self.vaddr_begin
    }

    /// Checks if the virtual address range is empty, i.e.
    /// if its length is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use elf::{Elf64Addr, Elf64AddrRange};
    ///
    /// let range1 = Elf64AddrRange {
    ///     vaddr_begin: 0x1000,
    ///     vaddr_end: 0x1000,
    /// };
    ///
    /// assert!(range1.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl TryFrom<(Elf64Addr, Elf64Xword)> for Elf64AddrRange {
    type Error = ElfError;

    /// Tries to create an [`Elf64AddrRange`] from a tuple of [`(Elf64Addr, Elf64Xword)`].
    ///
    /// This implementation calculates the `vaddr_end` based on the `vaddr_begin`
    /// and the provided [`Elf64Xword`] size, ensuring that the range is valid.
    ///
    /// # Errors
    ///
    /// Returns an [`ElfError::InvalidAddressRange`] if the calculation of `vaddr_end`
    /// results in an invalid address range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use elf::{Elf64Addr, Elf64AddrRange, Elf64Xword};
    ///
    /// let vaddr_begin = 0x1000;
    /// let size = 0x100;
    /// let range = Elf64AddrRange::try_from((vaddr_begin, size)).unwrap();
    ///
    /// assert_eq!(range.vaddr_begin, 0x1000);
    /// assert_eq!(range.vaddr_end, 0x1100);
    /// ```
    fn try_from(value: (Elf64Addr, Elf64Xword)) -> Result<Self, Self::Error> {
        let vaddr_begin = value.0;
        let size = value.1;
        let vaddr_end = vaddr_begin
            .checked_add(size)
            .ok_or(ElfError::InvalidAddressRange)?;
        Ok(Self {
            vaddr_begin,
            vaddr_end,
        })
    }
}

/// Compares two [`Elf64AddrRange`] instances for partial ordering. It returns
/// [`Some<Ordering>`] if there is a partial order, and [`None`] if there is no
/// order (i.e., if the ranges overlap without being equal).
///
/// # Arguments
///
/// * `other` - The other [`Elf64AddrRange`] to compare to.
///
/// # Returns
///
/// - [`Some<Ordering::Less>`] if [`Elf64AddrRange`] is less than `other`.
/// - [`Some<Ordering::Greater>`] if [`Elf64AddrRange`] is greater than `other`.
/// - [`Some<Ordering::Equal>`] if [`Elf64AddrRange`] is equal to `other`.
/// - [`None`] if there is no partial order (i.e., ranges overlap but are not equal).
///
/// # Examples
///
/// ```rust
/// use core::cmp::Ordering;
/// use elf::Elf64AddrRange;
///
/// let range1 = Elf64AddrRange {
///     vaddr_begin: 0x1000,
///     vaddr_end: 0x1100,
/// };
/// let range2 = Elf64AddrRange {
///     vaddr_begin: 0x1100,
///     vaddr_end: 0x1200,
/// };
///
/// assert_eq!(range1.partial_cmp(&range2), Some(Ordering::Less));
/// ```
impl PartialOrd for Elf64AddrRange {
    fn partial_cmp(&self, other: &Elf64AddrRange) -> Option<cmp::Ordering> {
        if self.vaddr_end <= other.vaddr_begin {
            Some(cmp::Ordering::Less)
        } else if self.vaddr_begin >= other.vaddr_end {
            Some(cmp::Ordering::Greater)
        } else if self == other {
            Some(cmp::Ordering::Equal)
        } else {
            None
        }
    }
}
