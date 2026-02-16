// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::BootImageError;
use crate::page_tables::KernelPageTables;
use crate::page_tables::PteType;
use crate::page_tables::is_page_aligned;
use crate::page_tables::page_align_up;
use crate::round_to_pages;

use core::slice;
use elf::Elf64File;
use igvm_defs::PAGE_SIZE_4K;

pub struct ElfSizes {
    pub virt_base: u64,
    pub virt_len: u64,
    pub phys_page_count: u64,
}

/// This function determines the virtual address bounds and physical size
/// required to contain a given ELF file.
pub fn get_elf_sizes(elf: &Elf64File<'_>) -> ElfSizes {
    // Enumerate the segments of this ELF file to count the total amount of
    // physical memory required.
    let mut page_count: u64 = 0;
    let vaddr_alloc_info = elf.image_load_vaddr_alloc_info();
    let vaddr_alloc_base = vaddr_alloc_info.range.vaddr_begin;
    for segment in elf.image_load_segment_iter(vaddr_alloc_base) {
        let segment_size = segment.vaddr_range.vaddr_end - segment.vaddr_range.vaddr_begin;
        page_count += round_to_pages(segment_size);
    }

    ElfSizes {
        virt_base: vaddr_alloc_base,
        virt_len: vaddr_alloc_info.range.vaddr_end - vaddr_alloc_base,
        phys_page_count: page_count,
    }
}

/// Loads a single ELF segment and returns its length in bytes.
fn load_elf_segment<F>(
    segment: elf::Elf64ImageLoadSegment<'_>,
    paddr: u64,
    page_tables: &mut KernelPageTables,
    add_page_data: &mut F,
) -> Result<u64, BootImageError>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    // Find the segment's bounds
    let segment_start = segment.vaddr_range.vaddr_begin;
    let segment_end = page_align_up(segment.vaddr_range.vaddr_end);
    let segment_len = segment_end - segment_start;

    // All ELF segments should be aligned to the page size. If not, there's
    // the risk of pvalidating a page twice, bail out if so. Note that the
    // ELF reading code had already verified that the individual segments,
    // with bounds specified as in the ELF file, are non-overlapping.
    if !is_page_aligned(segment_start) {
        return Err(BootImageError::ElfAlignment);
    }

    // Calculate the correct page table entry type based on this segment's
    // characteristics.
    let pte_type = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
        PteType::Executable
    } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
        PteType::RwData
    } else {
        PteType::RoData
    };

    // Map and validate the segment at the next contiguous physical address
    page_tables.map_range(segment_start, segment_len, paddr, pte_type)?;

    // Copy the segment contents into the boot image.  This requires specifying
    // the size of the segment to ensure that BSS data is fully expanded.
    add_page_data(paddr, Some(segment.file_contents), segment_len)?;

    Ok(segment_len)
}

/// Loads the kernel ELF and returns the entry point.
pub fn load_kernel_elf<F>(
    elf: &Elf64File<'_>,
    paddr_base: u64,
    expected_page_count: u64,
    page_tables: &mut KernelPageTables,
    add_page_data: &mut F,
) -> Result<u64, BootImageError>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    let vaddr_alloc_info = elf.image_load_vaddr_alloc_info();
    let vaddr_alloc_base = vaddr_alloc_info.range.vaddr_begin;

    // Map and populate the SVSM kernel ELF's PT_LOAD segments.
    assert_eq!(paddr_base & (PAGE_SIZE_4K - 1), 0);
    let mut phys_addr = paddr_base;
    for segment in elf.image_load_segment_iter(vaddr_alloc_base) {
        let size = load_elf_segment(segment, phys_addr, page_tables, add_page_data)?;

        // Update to the next contiguous physical address
        phys_addr += size;
    }

    // The amount of physical memory actually consumed must match the amount
    // of memory that was set aside.
    assert_eq!(phys_addr - paddr_base, expected_page_count * PAGE_SIZE_4K);

    // Apply relocations, if any
    if let Some(dyn_relocs) = elf
        .apply_dyn_relas(elf::Elf64X86RelocProcessor::new(), vaddr_alloc_base)
        .map_err(|_| BootImageError::ElfRelocs)?
    {
        for reloc in dyn_relocs {
            let Some(reloc) = reloc.map_err(|_| BootImageError::ElfRelocs)? else {
                continue;
            };
            // SAFETY: the relocation address is known to be correct. The ELF loader rejects
            // relocations that point outside a PT_LOAD segment.
            let dst = unsafe { slice::from_raw_parts_mut(reloc.dst as *mut u8, reloc.value_len) };
            let src = &reloc.value[..reloc.value_len];
            dst.copy_from_slice(src)
        }
    }

    Ok(elf.get_entry(vaddr_alloc_base))
}
