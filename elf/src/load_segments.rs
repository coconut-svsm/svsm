// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

extern crate alloc;

use super::types::*;
use super::Elf64AddrRange;
use super::Elf64File;
use super::Elf64FileRange;
use super::Elf64PhdrFlags;
use super::ElfError;
use alloc::vec::Vec;

use core::cmp;

/// Represents a collection of ELF64 load segments, each associated with an
/// address range and a program header index.
#[derive(Debug, Default, PartialEq)]
pub struct Elf64LoadSegments {
    segments: Vec<(Elf64AddrRange, Elf64Half)>,
}

impl Elf64LoadSegments {
    /// Creates a new empty [`Elf64LoadSegments`] instance.
    ///
    /// # Returns
    /// Returns a new [`Elf64LoadSegments`] with no segments.
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Finds the index of the first load segment whose address range does not come before
    /// the specified `range`.
    ///
    /// # Parameters
    /// - `range`: An [`Elf64AddrRange`] representing the address range to compare against.
    ///
    /// # Returns
    /// Returns [`Some(index)`] if a matching segment is found, where `index` is the index
    /// of the first such segment. Returns [`None`] if no matching segment is found.
    pub fn find_first_not_before(&self, range: &Elf64AddrRange) -> Option<usize> {
        let i = self.segments.partition_point(|segment| {
            matches!(segment.0.partial_cmp(range), Some(cmp::Ordering::Less))
        });

        if i != self.segments.len() {
            Some(i)
        } else {
            None
        }
    }

    /// Attempts to insert a new load segment into the collection.
    ///
    /// If the segment does not overlap with any existing segments, it is inserted
    /// into the collection.
    ///
    /// # Parameters
    /// - `segment`: An [`Elf64AddrRange`] representing the address range of the segment to insert.
    /// - `phdr_index`: An [`Elf64Half`] representing the program header index associated with
    ///   the segment.
    ///
    /// # Returns
    /// Returns [`Ok`] if the insertion is successful and there is no overlap with existing
    pub fn try_insert(
        &mut self,
        segment: Elf64AddrRange,
        phdr_index: Elf64Half,
    ) -> Result<(), ElfError> {
        let i = self.find_first_not_before(&segment);
        match i {
            Some(i) => {
                match segment.partial_cmp(&self.segments[i].0) {
                    Some(cmp::Ordering::Less) => {
                        // Ok, no overlap.
                        self.segments.insert(i, (segment, phdr_index));
                        Ok(())
                    }
                    _ => Err(ElfError::LoadSegmentConflict),
                }
            }
            None => {
                self.segments.push((segment, phdr_index));
                Ok(())
            }
        }
    }

    /// Looks up an address range and returns the associated program header index and offset
    /// within the segment.
    ///
    /// # Parameters
    /// - `range`: An [`Elf64AddrRange`] representing the address range to look up.
    ///
    /// # Returns
    /// Returns [`Some((phdr_index, offset))`] if the address range is found within a segment,
    /// where `phdr_index` is the program header index, and `offset` is the offset within
    pub fn lookup_vaddr_range(&self, range: &Elf64AddrRange) -> Option<(Elf64Half, Elf64Xword)> {
        let i = self.find_first_not_before(range)?;

        let segment = &self.segments[i];
        if segment.0.vaddr_begin <= range.vaddr_begin && range.vaddr_end <= segment.0.vaddr_end {
            let offset_in_segment = range.vaddr_begin - segment.0.vaddr_begin;
            Some((segment.1, offset_in_segment))
        } else {
            None
        }
    }

    /// Computes the total virtual address range covered by all load segments.
    ///
    /// # Returns
    /// Returns an [`Elf64AddrRange`] representing the total virtual address range covered by
    /// all load segments. If there are no segments, it returns a range with both boundaries set
    /// to 0.
    pub fn total_vaddr_range(&self) -> Elf64AddrRange {
        Elf64AddrRange {
            vaddr_begin: self.segments.first().map_or(0, |first| first.0.vaddr_begin),
            vaddr_end: self.segments.last().map_or(0, |last| last.0.vaddr_end),
        }
    }
}

/// Information about the allocation of a virtual address range
#[derive(Clone, Copy, Debug)]
pub struct Elf64ImageLoadVaddrAllocInfo {
    /// The virtual address (vaddr) range to allocate
    pub range: Elf64AddrRange,
    /// Optional alignment value set for PIE (Position-Independent
    /// Executable) executables, allowing a valid vaddr base to be allocated
    pub align: Option<Elf64Xword>,
}

/// Represents an ELF64 image load segment
#[derive(Debug)]
pub struct Elf64ImageLoadSegment<'a> {
    /// The virtual address (vaddr) range covering by this segment
    pub vaddr_range: Elf64AddrRange,
    /// The range in the ELF file covering this segment
    pub file_range: Elf64FileRange,
    /// The contents of the segment in the ELF file
    pub file_contents: &'a [u8],
    /// Flags associated with this segment
    pub flags: Elf64PhdrFlags,
}

/// An iterator over ELF64 image load segments within an ELF file
#[derive(Debug)]
pub struct Elf64ImageLoadSegmentIterator<'a> {
    pub elf_file: &'a Elf64File<'a>,
    pub load_base: Elf64Xword,
    pub next: usize,
}

impl<'a> Iterator for Elf64ImageLoadSegmentIterator<'a> {
    type Item = Elf64ImageLoadSegment<'a>;

    /// Advances the iterator to the next ELF64 image load segment and returns it.
    ///
    /// # Returns
    ///
    /// - [`Some<Elf64ImageLoadSegment>`] if there are more segments to iterate over.
    /// - [`None`] if all segments have been processed.
    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        if cur == self.elf_file.load_segments.segments.len() {
            return None;
        }
        self.next += 1;

        // Retrieve the program header (phdr) associated with the current segment
        let phdr_index = self.elf_file.load_segments.segments[cur].1;
        let phdr = self.elf_file.read_phdr(phdr_index);

        // Calculate the virtual address (vaddr) range based on the phdr information and load base
        let mut vaddr_range = phdr.vaddr_range();
        vaddr_range.vaddr_begin = vaddr_range.vaddr_begin.wrapping_add(self.load_base);
        vaddr_range.vaddr_end = vaddr_range.vaddr_end.wrapping_add(self.load_base);

        // Retrieve the file range for this phdr
        let file_range = phdr.file_range();
        // Extract the segment's file contents from the ELF file buffer
        let file_contents =
            &self.elf_file.elf_file_buf[file_range.offset_begin..file_range.offset_end];

        Some(Elf64ImageLoadSegment {
            vaddr_range,
            file_range,
            file_contents,
            flags: phdr.p_flags,
        })
    }
}
