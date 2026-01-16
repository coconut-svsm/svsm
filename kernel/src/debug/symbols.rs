// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

use core::slice;
use core::{ffi::CStr, fmt};

use bootlib::kernel_launch::KernelLaunchInfo;
use bootlib::symbols::KSym;
use rustc_demangle::{demangle, Demangle};

use crate::{address::VirtAddr, error::SvsmError, utils::immut_after_init::ImmutAfterInitCell};

/// A resolved symbol name and offset for any given address.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedSym {
    /// The name of the symbol.
    pub name: &'static CStr,
    /// The offset within the symbol.
    pub off: usize,
}

impl ResolvedSym {
    #[inline]
    const fn new(name: &'static CStr, off: usize) -> Self {
        Self { name, off }
    }

    /// Retrieves the demangled name for this symbol. This operation does
    /// not allocate. The returned type implements [`Display`](fmt::Display),
    /// so it can be printed in a straightforward way.
    pub fn demangled_name(&self) -> Demangle<'_> {
        demangle(self.name.to_str().unwrap_or_default())
    }
}

impl fmt::Display for ResolvedSym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}+{:#x}", self.demangled_name(), self.off)
    }
}

/// An address to symbol resolver, using ELF symbol information.
#[derive(Debug)]
struct SymResolver {
    symtab: &'static [KSym],
    strtab: &'static [u8],
}

impl SymResolver {
    const fn new(symtab: &'static [KSym], strtab: &'static [u8]) -> Self {
        Self { symtab, strtab }
    }

    /// Gets the name for the given symbol as a C string.
    fn get_sym_name(&self, sym: &KSym) -> &'static CStr {
        let slice = &self.strtab[sym.name as usize..];
        CStr::from_bytes_until_nul(slice).unwrap_or_default()
    }

    fn resolve_symbol(&self, addr: VirtAddr) -> Option<ResolvedSym> {
        let addr = usize::from(addr);

        // If we don't find an exact match, use the closest candidate.
        let mut min_diff = usize::MAX;
        let mut nearest_candidate = None;
        for sym in self.symtab.iter() {
            if sym.contains(addr) {
                let name = self.get_sym_name(sym);
                let offset = addr - sym.addr;
                return Some(ResolvedSym::new(name, offset));
            }

            let Some(diff) = addr.checked_sub(sym.addr) else {
                continue;
            };
            if diff < min_diff {
                min_diff = diff;
                nearest_candidate = Some(sym);
            }
        }

        nearest_candidate.map(|sym| ResolvedSym::new(self.get_sym_name(sym), addr - sym.addr))
    }
}

static SYM_RESOLVER: ImmutAfterInitCell<SymResolver> = ImmutAfterInitCell::uninit();

/// Initializes symbol data so that it can be used when [`resolve_symbol()`] is called.
pub fn init_symbols(li: &KernelLaunchInfo) -> Result<(), SvsmError> {
    let symtab_start = li.kernel_symtab_start;
    let strtab_start = li.kernel_strtab_start;

    // Data is not guaranteed to be there, so if that's the case just don't
    // initialize anything, which `resolve_symbol()` will handle gracefully.
    if symtab_start.is_null() || strtab_start.is_null() {
        return Ok(());
    }

    // Slices must be aligned to the type of the item they refer to. The strtab
    // is a byte slice, so it has no alignment requirements, but the symtab
    // slice has `KSym` items, so check.
    assert!(symtab_start.is_aligned());

    // SAFETY: we trust the `KernelLaunchInfo` passed by stage2 to contain valid addresses.
    let (symtab, strtab) = unsafe {
        (
            slice::from_raw_parts(symtab_start, li.kernel_symtab_len as usize),
            slice::from_raw_parts(strtab_start, li.kernel_strtab_len as usize),
        )
    };

    SYM_RESOLVER.init(SymResolver::new(symtab, strtab))?;
    Ok(())
}

/// Attempts to locate the symbol that corresponds to the given address.
pub fn resolve_symbol(addr: VirtAddr) -> Option<ResolvedSym> {
    SYM_RESOLVER.try_get_inner().ok()?.resolve_symbol(addr)
}
