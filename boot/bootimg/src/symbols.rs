// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

extern crate alloc;

use crate::BootImageError;
use crate::BootImageSpan;
use crate::heap::KernelPageHeap;
use alloc::vec::Vec;
use bootdefs::symbols::KSym;
use elf::{Elf64Strtab, Elf64Symtab};
use igvm_defs::PAGE_SIZE_4K;
use zerocopy::IntoBytes;

/// Parses out the `.symtab` and `.strtab` sections in the ELF binary to create
/// symbol information for the kernel. Returns two memory regions allocated
/// from the `KernelHeap`, each containing the information for the `.symtab` and
/// `.strtab` respectively.
pub fn load_kernel_symbols<F>(
    elf: &elf::Elf64File<'_>,
    heap: &mut KernelPageHeap,
    add_page_data: &mut F,
) -> Result<(BootImageSpan, BootImageSpan), BootImageError>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    let empty = BootImageSpan::new(0, 0);

    let Some((symtab, strtab)) = elf.symtab.as_ref().zip(elf.strtab.as_ref()) else {
        return Ok((empty, empty));
    };

    allocate_kernel_symbols(symtab, strtab, heap, add_page_data)
}

fn allocate_kernel_symbols<F>(
    symtab: &Elf64Symtab<'_>,
    strtab: &Elf64Strtab<'_>,
    heap: &mut KernelPageHeap,
    add_page_data: &mut F,
) -> Result<(BootImageSpan, BootImageSpan), BootImageError>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    let mut dst1 = PageCursor::new(heap, add_page_data);
    for i in 0..symtab.syms_num() {
        let sym = symtab.read_sym(i).map_err(|_| BootImageError::ElfSymbols)?;
        // `KSym` stores the size in a u32 since there should be no symbols
        // spanning more than 4GiB, and this helps shave off 8 bytes from
        // the struct (there is one per defined symbol, so this adds up to a
        // reduction of ~100KiB in memory footprint as of writing). Thus, in
        // the strange case that there is a symbol of this size, simply use the
        // maximum value of a u32.
        let size = u32::try_from(sym.st_size).unwrap_or(u32::MAX);
        dst1.write(KSym::new(sym.st_value as usize, size, sym.st_name).as_bytes())?;
    }
    dst1.flush()?;
    let symtab_span = dst1.span();

    let strtab_span = heap.allocate_and_add_pages(strtab.buf(), add_page_data)?;

    Ok((symtab_span, strtab_span))
}

/// A type that allows progressively adding data to a dynamically-sized portion
/// of memory.
struct PageCursor<'a, F> {
    span: BootImageSpan,
    data: Vec<u8>,
    heap: &'a mut KernelPageHeap,
    add_page_data: &'a mut F,
    closed: bool,
}

impl<'a, F> PageCursor<'a, F>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    /// Create an empty `PageCursor`. This does not allocate space in the
    /// kernel heap..
    fn new(heap: &'a mut KernelPageHeap, add_page_data: &'a mut F) -> Self {
        Self {
            span: BootImageSpan::new(0, 0),
            data: Vec::with_capacity(PAGE_SIZE_4K as usize),
            heap,
            add_page_data,
            closed: false,
        }
    }

    fn flush(&mut self) -> Result<(), BootImageError> {
        // If there is no accumuldated data, then there is nothing to flush.
        if self.data.is_empty() {
            return Ok(());
        }

        // Allocate a page from the kernel heap to hold this data and write it
        // to the image.
        let (paddr, vaddr) = self.heap.allocate_pages(1)?;

        // If this is the first page, then initialize the base address of the
        // span.
        if self.span.length == 0 {
            self.span.start = vaddr;
        }

        // Write the data to the allocated physical address.
        (self.add_page_data)(paddr, Some(&self.data), PAGE_SIZE_4K)?;

        // Expand the span of the allocation based on the returned virtual
        // address.
        self.span.length = vaddr + self.data.len() as u64 - self.span.start;

        // If the current data blob is not a full page, then it must be the
        // last page, and no more data can be added.
        if self.data.len() != PAGE_SIZE_4K as usize {
            self.closed = true;
        }

        // Prepare for more data.
        self.data.clear();

        Ok(())
    }

    /// Write some bytes into the cursor, committing data into the heap as
    /// needed.
    fn write(&mut self, val: &[u8]) -> Result<(), BootImageError> {
        // Do not permit adding data if the dataset has been closed.
        assert!(!self.closed);

        let mut offset: usize = 0;
        loop {
            // Copy data up to the limit of the page buffer.
            let bytes_to_write = val.len() - offset;
            let bytes_available = (PAGE_SIZE_4K as usize) - self.data.len();
            if bytes_to_write < bytes_available {
                self.data
                    .extend_from_slice(&val[offset..offset + bytes_to_write]);
                return Ok(());
            }
            self.data
                .extend_from_slice(&val[offset..offset + bytes_available]);

            // Flush the full buffer and prepare to consume more data.
            self.flush()?;
            offset += bytes_available;
        }
    }

    /// Returns the contiguous memory span that was allocated by the
    /// `PageCursor`.
    fn span(&self) -> BootImageSpan {
        self.span
    }
}
