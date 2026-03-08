// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::BootImageError;
use crate::BootImageSpan;
use crate::add_page_contents;
use crate::elf::ElfSizes;
use crate::round_to_pages;

use igvm_defs::PAGE_SIZE_4K;

#[derive(Debug)]
pub struct KernelPageHeap {
    virt_base: u64,
    phys_base: u64,
    page_count: u64,
    next_free: u64,
}

impl KernelPageHeap {
    fn create(phys_base: u64, page_count: u64, virt_base: u64) -> Self {
        Self {
            virt_base,
            phys_base,
            page_count,
            next_free: 0,
        }
    }

    pub fn phys_base(&self) -> u64 {
        self.phys_base
    }

    pub fn next_free(&self) -> u64 {
        self.next_free
    }

    /// Allocates pages out of the heap memory area.  The returned value is a
    /// tuple containing the physical address and virtual address of the
    /// allocation.
    pub fn allocate_pages(&mut self, page_count: u64) -> Result<(u64, u64), BootImageError> {
        // Allocation can only be successful if the heap is large enough to
        // accommodate the allocation request.
        if self.next_free + page_count <= self.page_count {
            let offset = self.next_free * PAGE_SIZE_4K;
            let (phys, virt) = (self.phys_base + offset, self.virt_base + offset);
            self.next_free += page_count;
            Ok((phys, virt))
        } else {
            Err(BootImageError::HeapTooSmall)
        }
    }

    /// Allocates pages out of the heap memory area and adds the associated
    /// data to the boot image.
    pub fn allocate_and_add_pages<F>(
        &mut self,
        data: &[u8],
        add_page_data: &mut F,
    ) -> Result<BootImageSpan, BootImageError>
    where
        F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
    {
        let len = data.len() as u64;
        let (paddr, vaddr) = self.allocate_pages(round_to_pages(len))?;
        add_page_contents(add_page_data, paddr, data)?;
        Ok(BootImageSpan::new(vaddr, len))
    }
}

/// Creates a structure used to describe the kernel heap and the associated
/// allocations that are made as the boot image is prepared.  The kernel heap
/// begins immediately after the kernel image and extends to the top of the
/// allocated kernel memory region.
pub fn create_kernel_heap(
    kernel_phys_base: u64,
    kernel_page_count: u64,
    kernel_elf_sizes: &ElfSizes,
    direct_map_base: u64,
) -> Result<KernelPageHeap, BootImageError> {
    // Calculate the base and size of the heap as the region that follows the
    // kernel image.
    let kernel_size = kernel_elf_sizes.phys_page_count * PAGE_SIZE_4K;
    let heap_pstart = kernel_phys_base + kernel_size;

    // Compute size.
    let heap_size = kernel_page_count
        .checked_sub(kernel_elf_sizes.phys_page_count)
        .ok_or(BootImageError::KernelTooBig)?;

    // Calculate the base virtual address of the heap.
    let heap_vstart = direct_map_base + kernel_size;
    let heap = KernelPageHeap::create(heap_pstart, heap_size, heap_vstart);

    Ok(heap)
}
