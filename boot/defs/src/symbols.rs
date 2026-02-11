// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// A smaller version of `Elf64Sym`.
///
/// Defines the format of the symbol information passed to the SVSM kernel to be
/// able to perform address to symbol resolution.
#[repr(C)]
#[derive(Clone, Copy, Debug, IntoBytes, Immutable, FromBytes)]
pub struct KSym {
    /// The starting address of the symbol.
    pub addr: usize,
    /// The span of the symbol in the address space.
    pub size: u32,
    /// The name of the symbol, as an index into the `strtab`.
    pub name: u32,
}

impl KSym {
    pub const fn new(addr: usize, size: u32, name: u32) -> Self {
        Self { addr, size, name }
    }

    /// Checks whether a given address falls within the span of this symbol.
    pub const fn contains(&self, addr: usize) -> bool {
        let end = self.addr + self.size as usize;
        self.addr <= addr && addr < end
    }
}
