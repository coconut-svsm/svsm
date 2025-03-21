// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::pagetable::PTEntryFlags;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::percpu::this_cpu;
use crate::cpu::tlb::flush_address_percpu;
use crate::error::SvsmError;
use crate::insn_decode::{InsnError, InsnMachineMem};
use crate::mm::virtualrange::VRangeAlloc;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;
use core::marker::PhantomData;

/// Guard for a per-CPU page mapping to ensure adequate cleanup if drop.
#[derive(Debug)]
#[must_use = "if unused the mapping will immediately be unmapped"]
pub struct PerCPUPageMappingGuard {
    mapping: VRangeAlloc,
}

impl PerCPUPageMappingGuard {
    /// Creates a new [`PerCPUPageMappingGuard`] for the specified physical
    /// address range and alignment.
    ///
    /// # Arguments
    ///
    /// * `paddr_start` - The starting physical address of the range.
    /// * `paddr_end` - The ending physical address of the range.
    /// * `alignment` - The desired alignment for the mapping.
    ///
    /// # Returns
    ///
    /// A `Result` containing the [`PerCPUPageMappingGuard`] if successful,
    /// or an `SvsmError` if an error occurs.
    ///
    /// # Panics
    ///
    /// Panics if either `paddr_start`, the size, or `paddr_end`, are not
    /// aligned.
    pub fn create(
        paddr_start: PhysAddr,
        paddr_end: PhysAddr,
        alignment: usize,
    ) -> Result<Self, SvsmError> {
        let align_mask = (PAGE_SIZE << alignment) - 1;
        let size = paddr_end - paddr_start;
        assert!((size & align_mask) == 0);
        assert!((paddr_start.bits() & align_mask) == 0);
        assert!((paddr_end.bits() & align_mask) == 0);

        let flags = PTEntryFlags::data();
        let huge = ((paddr_start.bits() & (PAGE_SIZE_2M - 1)) == 0)
            && ((paddr_end.bits() & (PAGE_SIZE_2M - 1)) == 0);

        let mapping = if huge {
            let range = VRangeAlloc::new_2m(size, 0)?;
            this_cpu()
                .get_pgtable()
                .map_region_2m(range.region(), paddr_start, flags, false)?;
            range
        } else {
            let range = VRangeAlloc::new_4k(size, 0)?;
            this_cpu()
                .get_pgtable()
                .map_region_4k(range.region(), paddr_start, flags, false)?;
            range
        };

        Ok(Self { mapping })
    }

    /// Creates a new [`PerCPUPageMappingGuard`] for a 4KB page at the
    /// specified physical address, or an `SvsmError` if an error occurs.
    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        Self::create(paddr, paddr + PAGE_SIZE, 0)
    }

    /// Returns the virtual address associated with the guard.
    pub fn virt_addr(&self) -> VirtAddr {
        self.mapping.region().start()
    }

    /// Creates a virtual contigous mapping for the given 4k physical pages which
    /// may not be contiguous in physical memory.
    ///
    /// # Arguments
    ///
    /// * `pages`: A slice of tuple containing `PhysAddr` objects representing the
    ///   4k page to map and its shareability.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` that contains a `PerCPUPageMappingGuard`
    /// object on success. The `PerCPUPageMappingGuard` object represents the page
    /// mapping that was created. If an error occurs while creating the page
    /// mapping, it returns a `SvsmError`.
    pub fn create_4k_pages(pages: &[(PhysAddr, bool)]) -> Result<Self, SvsmError> {
        let mapping = VRangeAlloc::new_4k(pages.len() * PAGE_SIZE, 0)?;
        let flags = PTEntryFlags::data();

        let mut pgtable = this_cpu().get_pgtable();
        for (vaddr, (paddr, shared)) in mapping
            .region()
            .iter_pages(PageSize::Regular)
            .zip(pages.iter().copied())
        {
            assert!(paddr.is_page_aligned());
            pgtable.map_4k(vaddr, paddr, flags)?;
            if shared {
                pgtable.set_shared_4k(vaddr)?;
            }
        }

        Ok(Self { mapping })
    }
}

impl Drop for PerCPUPageMappingGuard {
    fn drop(&mut self) {
        let region = self.mapping.region();
        let size = if self.mapping.huge() {
            this_cpu().get_pgtable().unmap_region_2m(region);
            PageSize::Huge
        } else {
            this_cpu().get_pgtable().unmap_region_4k(region);
            PageSize::Regular
        };
        // This iterative flush is acceptable for same-CPU mappings because no
        // broadcast is involved for each iteration.
        for page in region.iter_pages(size) {
            flush_address_percpu(page);
        }
    }
}

/// Represents a guard for a specific memory range mapping, which will
/// unmap the specific memory range after being dropped.
#[derive(Debug)]
pub struct MemMappingGuard<T> {
    // The guard of holding the temporary mapping for a specific memory range.
    guard: PerCPUPageMappingGuard,
    // The starting offset of the memory range.
    start_off: usize,

    phantom: PhantomData<T>,
}

impl<T: Copy> MemMappingGuard<T> {
    /// Creates a new `MemMappingGuard` with the given `PerCPUPageMappingGuard`
    /// and starting offset.
    ///
    /// # Arguments
    ///
    /// * `guard` - The `PerCPUPageMappingGuard` to associate with the `MemMappingGuard`.
    /// * `start_off` - The starting offset for the memory mapping.
    ///
    /// # Returns
    ///
    /// Self is returned.
    pub fn new(guard: PerCPUPageMappingGuard, start_off: usize) -> Result<Self, SvsmError> {
        if start_off >= guard.mapping.region().len() {
            Err(SvsmError::Mem)
        } else {
            Ok(Self {
                guard,
                start_off,
                phantom: PhantomData,
            })
        }
    }

    /// Reads data from a virtual address region specified by an offset
    ///
    /// # Safety
    ///
    /// The caller must verify not to read from arbitrary memory regions. The region to read must
    /// be checked to guarantee the memory is mapped by the guard and is valid for reading.
    ///
    /// # Arguments
    ///
    /// * `offset`: The offset (in unit of `size_of::<T>()`) from the start of the virtual address
    ///   region to read from.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` that indicates the success or failure of the operation.
    /// If the read operation is successful, it returns `Ok(T)` which contains the read back data.
    /// If the virtual address region cannot be retrieved, it returns `Err(SvsmError::Mem)`.
    pub unsafe fn read(&self, offset: usize) -> Result<T, SvsmError> {
        let size = core::mem::size_of::<T>();
        self.virt_addr_region(offset * size, size)
            .map_or(Err(SvsmError::Mem), |region| unsafe {
                Ok(*(region.start().as_ptr::<T>()))
            })
    }

    /// Writes data from a provided data into a virtual address region specified by an offset.
    ///
    /// # Safety
    ///
    /// The caller must verify not to write to arbitrary memory regions. The memory region to write
    /// must be checked to guarantee the memory is mapped by the guard and is valid for writing.
    ///
    /// # Arguments
    ///
    /// * `offset`: The offset (in unit of `size_of::<T>()`) from the start of the virtual address
    ///   region to write to.
    /// * `data`: Data to write.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` that indicates the success or failure of the operation.
    /// If the write operation is successful, it returns `Ok(())`. If the virtual address region
    /// cannot be retrieved or if the buffer size is larger than the region size, it returns
    /// `Err(SvsmError::Mem)`.
    pub unsafe fn write(&self, offset: usize, data: T) -> Result<(), SvsmError> {
        let size = core::mem::size_of::<T>();
        self.virt_addr_region(offset * size, size)
            .map_or(Err(SvsmError::Mem), |region| {
                unsafe {
                    *(region.start().as_mut_ptr::<T>()) = data;
                }
                Ok(())
            })
    }

    fn virt_addr_region(&self, offset: usize, len: usize) -> Option<MemoryRegion<VirtAddr>> {
        if len != 0 {
            MemoryRegion::checked_new(
                self.guard
                    .virt_addr()
                    .checked_add(self.start_off + offset)?,
                len,
            )
            .filter(|v| self.guard.mapping.region().contains_region(v))
        } else {
            None
        }
    }
}

impl<T: Copy> InsnMachineMem for MemMappingGuard<T> {
    type Item = T;

    /// Safety: See the MemMappingGuard's read() method documentation for safety requirements.
    unsafe fn mem_read(&self) -> Result<Self::Item, InsnError> {
        unsafe { self.read(0).map_err(|_| InsnError::MemRead) }
    }

    /// Safety: See the MemMappingGuard's write() method documentation for safety requirements.
    unsafe fn mem_write(&mut self, data: Self::Item) -> Result<(), InsnError> {
        unsafe { self.write(0, data).map_err(|_| InsnError::MemWrite) }
    }
}
