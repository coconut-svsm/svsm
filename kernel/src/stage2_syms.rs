// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

use bootlib::symbols::KSym;
use elf::{Elf64Strtab, Elf64Symtab};
use svsm::{
    address::VirtAddr,
    error::SvsmError,
    types::PAGE_SIZE,
    utils::{round_to_pages, MemoryRegion},
};
use zerocopy::IntoBytes;

use super::KernelHeap;

/// Parses out the `.symtab` and `.strtab` sections in the ELF binary to create
/// symbol information for the kernel. Returns two memory regions allocated
/// from the `KernelHeap`, each containing the information for the `.symtab` and
/// `.strtab` respectively.
pub fn load_kernel_symbols(
    elf: &elf::Elf64File<'_>,
    heap: &mut KernelHeap,
) -> (MemoryRegion<VirtAddr>, MemoryRegion<VirtAddr>) {
    let empty = MemoryRegion::new(VirtAddr::null(), 0);

    let Some((symtab, strtab)) = elf.symtab.as_ref().zip(elf.strtab.as_ref()) else {
        log::info!("No kernel symbols!");
        return (empty, empty);
    };

    allocate_kernel_symbols(symtab, strtab, heap).unwrap_or_else(|e| {
        log::warn!("Failed to allocate memory for kernel symbols: {e:?}");
        (empty, empty)
    })
}

fn allocate_kernel_symbols(
    symtab: &Elf64Symtab<'_>,
    strtab: &Elf64Strtab<'_>,
    heap: &mut KernelHeap,
) -> Result<(MemoryRegion<VirtAddr>, MemoryRegion<VirtAddr>), SvsmError> {
    let mut dst1 = PageCursor::new(heap);
    for i in 0..symtab.syms_num() {
        let sym = symtab.read_sym(i)?;
        // `KSym` stores the size in a u32 since there should be no symbols
        // spanning more than 4GiB, and this helps shave off 8 bytes from
        // the struct (there is one per defined symbol, so this adds up to a
        // reduction of ~100KiB in memory footprint as of writing). Thus, in
        // the strange case that there is a symbol of this size, simply use the
        // maximum value of a u32.
        let size = u32::try_from(sym.st_size).unwrap_or(u32::MAX);
        dst1.write(KSym::new(sym.st_value as usize, size, sym.st_name).as_bytes())?;
    }
    let r1 = MemoryRegion::new(dst1.region.start(), dst1.pos);

    let mut dst2 = PageCursor::new(heap);
    dst2.write(strtab.buf())?;
    let r2 = MemoryRegion::new(dst2.region.start(), dst2.pos);

    Ok((r1, r2))
}

/// A type that allows progressively reserving a dynamically-sized portion of
/// memory.
struct PageCursor<'a> {
    region: MemoryRegion<VirtAddr>,
    pos: usize,
    heap: &'a mut KernelHeap,
}

impl<'a> PageCursor<'a> {
    /// Create an empty `PageCursor`. This does not allocate.
    fn new(heap: &'a mut KernelHeap) -> Self {
        Self {
            region: MemoryRegion::new(VirtAddr::null(), 0),
            pos: 0,
            heap,
        }
    }

    /// Write some bytes into the cursor, allocating more memory in the process
    /// if needed.
    fn write(&mut self, val: &[u8]) -> Result<(), SvsmError> {
        let new_pos = self.pos + val.len();
        if let Some(need) = new_pos.checked_sub(self.region.len()) {
            self.get_pages(need)?;
        };

        let dst = self.region.start() + self.pos;
        // SAFETY: we trust the allocator to reserve memory properly.
        // The source and destination are byte slices, so there are
        // no invalid representations nor alignment requirements.
        unsafe {
            dst.as_mut_ptr::<u8>()
                .copy_from_nonoverlapping(val.as_ptr(), val.len())
        };

        self.pos = new_pos;
        Ok(())
    }

    /// Extends the cursor's allocation by requesting pages to satisfy the
    /// requested additional length.
    fn get_pages(&mut self, len: usize) -> Result<(), SvsmError> {
        let pages = round_to_pages(len);
        let page = self.heap.allocate_pages(pages)?.0;
        let region = MemoryRegion::new(page, pages * PAGE_SIZE);
        if self.region.is_empty() {
            self.region = region;
            return Ok(());
        }

        // This should never happen, as the allocator returns contiguous
        // pages, and we have an exclusive reference to it. Leave this to
        // catch a potential change in the allocator.
        assert!(self.region.contiguous(&region));

        self.region = self.region.expand(region.len());
        Ok(())
    }
}
