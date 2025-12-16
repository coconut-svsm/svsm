// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::BootImageError;
use crate::PGTABLE_LVL3_IDX_PTE_SELFMAP;
use crate::defs::add_page_contents;
use crate::heap::KernelPageHeap;

extern crate alloc;

use alloc::boxed::Box;
use core::mem::MaybeUninit;
use core::slice;
use igvm_defs::PAGE_SIZE_4K;

const PTE_SHIFT: u64 = 9;
const PTE_PER_PAGE: u64 = 1 << PTE_SHIFT;

pub fn is_page_aligned(addr: u64) -> bool {
    (addr & (PAGE_SIZE_4K - 1)) == 0
}

pub fn page_align_up(size: u64) -> u64 {
    (size + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1)
}

// This uses an explicit divide implementation because the compiler can
// optimize the divide because the page size is a power of two.
#[allow(clippy::manual_div_ceil)]
pub fn round_to_pages(size: u64) -> u64 {
    (size + (PAGE_SIZE_4K - 1)) / PAGE_SIZE_4K
}

fn pte_index(vaddr: u64, level: u64) -> u64 {
    vaddr >> (PTE_SHIFT * level + 12)
}

#[derive(Clone, Copy, Debug)]
pub enum PteType {
    SelfMap,
    Pxe,
    RwData,
    RoData,
    Executable,
}

#[derive(Debug)]
struct X64Pte {
    pte: u64,
}

impl X64Pte {
    fn new(paddr: u64, pte_type: PteType) -> Self {
        // All addresses must be aligned to a page boundary.
        assert_eq!(paddr & (PAGE_SIZE_4K - 1), 0);

        let flags = match pte_type {
            // All PTEs include global (100) and accessed (020) and present
            // (001).  PxEs do not include the global bit.
            // Writable = 002
            // Dirty = 040
            // NX = 8000000000000000
            PteType::SelfMap => 0x80000000_00000063,
            PteType::Pxe => 0x063,
            PteType::RwData => 0x80000000_00000163,
            PteType::RoData => 0x80000000_00000121,
            PteType::Executable => 0x00000000_00000121,
        };
        Self { pte: paddr | flags }
    }
}

#[derive(Debug)]
struct PageTableContents {
    allocation: Box<[MaybeUninit<X64Pte>]>,
}

impl PageTableContents {
    fn new(count: usize) -> Self {
        // Allocation of a zeroed slice is unstable in the current version of
        // the toolchain, so instead, an uninitialized allocation is made and
        // then zeroed before returning to the caller.
        let allocation = Box::new_uninit_slice(count);
        let mut contents = Self { allocation };
        contents.reset();
        contents
    }

    /// Resets the content of the allocated page tables to all zero.
    fn reset(&mut self) {
        // SAFETY: the box will correctly expose the pointer and length of the
        // allocation, and the PTE array can safely have its state by
        // resetting its contents back to zero.
        unsafe {
            self.allocation
                .as_mut_ptr()
                .write_bytes(0, self.allocation.len());
        }
    }

    fn entry(&self, index: usize) -> &X64Pte {
        // SAFETY: the allocation was made as a slice of MaybeUninit so it
        // is known to be both aligned and non-null, and it is known to have
        // been initialized either through zero-initialization or by a
        // subsequent overwrite of a valid value.
        unsafe { &*self.allocation[index].as_ptr() }
    }

    fn entry_mut(&mut self, index: usize) -> &mut X64Pte {
        // SAFETY: the allocation was made as a slice of MaybeUninit so it
        // is known to be both aligned and non-null, and it is known to have
        // been initialized either through zero-initialization or by a
        // subsequent overwrite of a valid value.
        unsafe { &mut *self.allocation[index].as_mut_ptr() }
    }

    /// Sets the entry at the specified index within the allocated page table
    /// array.
    fn set_entry(&mut self, index: usize, paddr: u64, pte_type: PteType) {
        *self.entry_mut(index) = X64Pte::new(paddr, pte_type);
    }

    /// Reads the entry at the specified index within the allocated page table
    /// array.
    fn read_entry(&self, index: usize) -> u64 {
        self.entry(index).pte
    }

    /// Returns a slice to the specified page within the allocated page tables.
    /// The index here represents the page index, not the PTE index.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the allocation was made as a slice of MaybeUninit so it is
        // known to have been initialized either through zero-initialization or
        // by a subsequent overwrite of a valid value.  The assert above
        // verifies that the bounds of the requested page are within the bounds
        // of the allocation.
        unsafe {
            slice::from_raw_parts(
                self.allocation.as_ptr() as *const u8,
                self.allocation.len() * size_of::<X64Pte>(),
            )
        }
    }
}

#[derive(Debug)]
pub struct KernelPageTables {
    pte_allocation: PageTableContents,
    starting_index: u64,
    starting_paddr: u64,
    pte_count: usize,
    total_pt_pages: u64,
    paging_root: u64,
    root_vaddr: u64,
    kernel_pdpt_paddr: u64,
    kernel_pml4e_index: usize,
}

impl KernelPageTables {
    pub fn root_vaddr(&self) -> u64 {
        self.root_vaddr
    }

    pub fn kernel_pdpt_paddr(&self) -> u64 {
        self.kernel_pdpt_paddr
    }

    pub fn kernel_pml4e_index(&self) -> u32 {
        self.kernel_pml4e_index as u32
    }

    pub fn map_range(
        &mut self,
        vaddr: u64,
        mut len: u64,
        mut paddr: u64,
        pte_type: PteType,
    ) -> Result<(), BootImageError> {
        assert!(is_page_aligned(vaddr));
        assert!(is_page_aligned(paddr));
        assert_ne!(len, 0);

        // Calculate the starting PTE index for the range to be mapped.
        let starting_pte_index = pte_index(vaddr, 0);
        if starting_pte_index < self.starting_index {
            return Err(BootImageError::BadKernelAddress);
        }
        let mut pte_index: usize = (starting_pte_index - self.starting_index)
            .try_into()
            .unwrap();

        // Set each PTE in the specified range.
        loop {
            if pte_index >= self.pte_count {
                return Err(BootImageError::BadKernelAddress);
            }
            self.pte_allocation.set_entry(pte_index, paddr, pte_type);
            if len <= PAGE_SIZE_4K {
                return Ok(());
            }
            len -= PAGE_SIZE_4K;
            pte_index += 1;
            paddr += PAGE_SIZE_4K;
        }
    }

    pub fn add_to_image<F>(&self, add_page_data: &mut F) -> Result<(u64, u64), BootImageError>
    where
        F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
    {
        add_page_contents(
            add_page_data,
            self.starting_paddr,
            self.pte_allocation.as_bytes(),
        )
        .and(Ok((self.paging_root, self.total_pt_pages)))
    }
}

pub fn setup_kernel_page_tables<F>(
    kernel_virt_base: u64,
    kernel_heap: &mut KernelPageHeap,
    add_page_data: &mut F,
) -> Result<KernelPageTables, BootImageError>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    // Calculate the virtual span of the kernel region.  This extends from the
    // base of the kernel virtual address region through the end of the heap.
    let heap_end = kernel_heap.virt_base() + (kernel_heap.page_count() * PAGE_SIZE_4K);
    let kernel_virt_len = heap_end - kernel_virt_base;
    let pte_count: usize = round_to_pages(kernel_virt_len)
        .try_into()
        .map_err(|_| BootImageError::KernelRangeTooLarge)?;

    // Calculate start and end PTE index values and the size of the leaf page
    // tables.
    let start_pte_index = (pte_index(kernel_virt_base, 0) & (PTE_PER_PAGE - 1)) as usize;
    let end_pte_index = start_pte_index + pte_count;
    let pde_count = round_to_pages((end_pte_index * size_of::<X64Pte>()) as u64) as usize;

    // Calculate the number of PDEs that will be required to map the page
    // tables.  This page table construction logic requires all PDEs to fit
    // within a single page in order to ensure that only one PML4E and only
    // one PDPE need to be allocated.
    let start_pde_index = (pte_index(kernel_virt_base, 1) & (PTE_PER_PAGE - 1)) as usize;
    let end_pde_index = start_pde_index + pde_count;
    if end_pde_index as u64 > PTE_PER_PAGE {
        return Err(BootImageError::KernelRangeTooLarge);
    }

    // Allocate a physical address range to hold the entire page table
    // hierarchy.  This is one page for each of the leaf page table pages,
    // plus one page each for the page directory, the PDPE, and the PML4E.
    let total_pt_pages = end_pde_index as u64 + 3;
    let (paging_root, root_vaddr) = kernel_heap.allocate_pages(total_pt_pages)?;

    // Allocate memory to describe the page tables.
    let pte_allocation = PageTableContents::new(end_pte_index);

    // Populate the upper levels of the paging hierarchy down to the page
    // directory level.
    let mut paddr = paging_root;

    let mut pxe_allocation = PageTableContents::new(PTE_PER_PAGE as usize);

    // Set the self-map entry to point to the root page table page.
    pxe_allocation.set_entry(PGTABLE_LVL3_IDX_PTE_SELFMAP, paging_root, PteType::SelfMap);

    let pml4e_index = (pte_index(kernel_virt_base, 3) & (PTE_PER_PAGE - 1)) as usize;
    let pdpt_paddr = paddr + PAGE_SIZE_4K;
    if pxe_allocation.read_entry(pml4e_index) != 0 {
        return Err(BootImageError::SelfMapConflict);
    }
    pxe_allocation.set_entry(pml4e_index, pdpt_paddr, PteType::Pxe);
    add_page_contents(add_page_data, paddr, pxe_allocation.as_bytes())?;

    paddr += PAGE_SIZE_4K;
    pxe_allocation.reset();
    let pdpe_index = (pte_index(kernel_virt_base, 2) & (PTE_PER_PAGE - 1)) as usize;
    pxe_allocation.set_entry(pdpe_index, paddr + PAGE_SIZE_4K, PteType::Pxe);
    add_page_contents(add_page_data, paddr, pxe_allocation.as_bytes())?;

    paddr += PAGE_SIZE_4K;
    let pte_paddr = paddr + PAGE_SIZE_4K;
    pxe_allocation.reset();
    for pde_index in start_pde_index..end_pde_index {
        let offset = (pde_index - start_pde_index) * PAGE_SIZE_4K as usize;
        let pt_addr = pte_paddr + offset as u64;
        pxe_allocation.set_entry(pde_index, pt_addr, PteType::Pxe);
    }
    add_page_contents(add_page_data, paddr, pxe_allocation.as_bytes())?;

    Ok(KernelPageTables {
        pte_allocation,
        starting_index: pte_index(kernel_virt_base, 0),
        paging_root,
        root_vaddr,
        starting_paddr: paddr + PAGE_SIZE_4K,
        pte_count,
        total_pt_pages,
        kernel_pdpt_paddr: pdpt_paddr,
        kernel_pml4e_index: pml4e_index,
    })
}
