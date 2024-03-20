// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

#![no_std]

mod addr_range;
mod dynamic;
mod error;
mod file;
mod file_range;
mod header;
mod load_segments;
mod program_header;
mod relocation;
mod section_header;
mod syms;
mod types;

pub use addr_range::Elf64AddrRange;
pub use dynamic::{Elf64Dynamic, Elf64DynamicRelocTable};
pub use error::ElfError;
pub use file::Elf64File;
pub use file_range::Elf64FileRange;
use header::Elf64Hdr;
pub use load_segments::{
    Elf64ImageLoadSegment, Elf64ImageLoadSegmentIterator, Elf64ImageLoadVaddrAllocInfo,
    Elf64LoadSegments,
};
pub use program_header::{Elf64Phdr, Elf64PhdrFlags};
pub use relocation::{
    Elf64AppliedRelaIterator, Elf64Rela, Elf64Relas, Elf64RelocOp, Elf64RelocProcessor,
    Elf64X86RelocProcessor,
};
pub use section_header::{Elf64Shdr, Elf64ShdrFlags, Elf64ShdrIterator};
pub use syms::{Elf64Strtab, Elf64Sym, Elf64Symtab};
pub use types::*;

#[cfg(test)]
mod tests;
