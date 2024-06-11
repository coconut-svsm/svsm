// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::pagetable::PTEntryFlags;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::percpu::this_cpu;
use crate::cpu::tlb::flush_address_sync;
use crate::error::SvsmError;
use crate::insn_decode::{InsnError, InsnMachineMem};
use crate::mm::virtualrange::{
    virt_alloc_range_2m, virt_alloc_range_4k, virt_free_range_2m, virt_free_range_4k,
};
use crate::types::{Bytes, PageSize, PAGE_SIZE, PAGE_SIZE_2M};

use crate::utils::MemoryRegion;

#[derive(Debug)]
#[must_use = "if unused the mapping will immediately be unmapped"]
pub struct PerCPUPageMappingGuard {
    mapping: MemoryRegion<VirtAddr>,
    huge: bool,
}

impl PerCPUPageMappingGuard {
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
        let raw_mapping = if huge {
            let region = virt_alloc_range_2m(size, 0)?;
            if let Err(e) = this_cpu()
                .get_pgtable()
                .map_region_2m(region, paddr_start, flags)
            {
                virt_free_range_2m(region);
                return Err(e);
            }
            region
        } else {
            let region = virt_alloc_range_4k(size, 0)?;
            if let Err(e) = this_cpu()
                .get_pgtable()
                .map_region_4k(region, paddr_start, flags)
            {
                virt_free_range_4k(region);
                return Err(e);
            }
            region
        };

        Ok(PerCPUPageMappingGuard {
            mapping: raw_mapping,
            huge,
        })
    }

    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        Self::create(paddr, paddr + PAGE_SIZE, 0)
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.mapping.start()
    }

    /// Creates a virtual contigous mapping for the given 4k physical pages which
    /// may not be contiguous in physical memory.
    ///
    /// # Arguments
    ///
    /// * `pages`: A slice of tuple containing `PhysAddr` objects representing the
    /// 4k page to map and its shareability.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` that contains a `PerCPUPageMappingGuard`
    /// object on success. The `PerCPUPageMappingGuard` object represents the page
    /// mapping that was created. If an error occurs while creating the page
    /// mapping, it returns a `SvsmError`.
    pub fn create_4k_pages(pages: &[(PhysAddr, bool)]) -> Result<Self, SvsmError> {
        let region = virt_alloc_range_4k(pages.len() * PAGE_SIZE, 0)?;
        let flags = PTEntryFlags::data();

        for (i, addr) in region.iter_pages(PageSize::Regular).enumerate() {
            assert!(pages[i].0.is_aligned(PAGE_SIZE));

            this_cpu()
                .get_pgtable()
                .map_4k(addr, pages[i].0, flags)
                .and_then(|_| {
                    if pages[i].1 {
                        this_cpu().get_pgtable().set_shared_4k(addr)
                    } else {
                        Ok(())
                    }
                })
                .map_err(|e| {
                    virt_free_range_4k(region);
                    e
                })?;
        }

        Ok(PerCPUPageMappingGuard {
            mapping: region,
            huge: false,
        })
    }
}

impl Drop for PerCPUPageMappingGuard {
    fn drop(&mut self) {
        if self.huge {
            this_cpu().get_pgtable().unmap_region_2m(self.mapping);
            virt_free_range_2m(self.mapping);
        } else {
            this_cpu().get_pgtable().unmap_region_4k(self.mapping);
            virt_free_range_4k(self.mapping);
        }
        flush_address_sync(self.mapping.start());
    }
}

/// Represents a guard for a specific memory range mapping, which will
/// unmap the specific memory range after being dropped.
#[derive(Debug)]
pub struct MemMappingGuard {
    // The guard of holding the temperary mapping for a specific memory range.
    guard: PerCPUPageMappingGuard,
    // The starting offset of the memory range.
    start_off: usize,
}

impl MemMappingGuard {
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
    /// A `Result` containing the `MemMappingGuard` if successful, or a `SvsmError` if the starting
    /// offset is out of bounds.
    pub fn new(guard: PerCPUPageMappingGuard, start_off: usize) -> Result<Self, SvsmError> {
        if start_off >= guard.mapping.len() {
            Err(SvsmError::Mem)
        } else {
            Ok(Self { guard, start_off })
        }
    }

    /// Reads data from a virtual address region specified by an offset and size into a provided
    /// buffer.
    ///
    /// # Arguments
    ///
    /// * `offset`: The offset from the start of the virtual address region to read from.
    /// * `size`: The number of bytes to read.
    /// * `buf`: A mutable reference to a byte array where the read data will be stored.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` that indicates the success or failure of the operation.
    /// If the read operation is successful, it returns `Ok(())`. If the virtual address region
    /// cannot be retrieved, it returns `Err(SvsmError::Mem)`.
    pub fn read(&self, offset: usize, size: usize, buf: &mut [u8]) -> Result<(), SvsmError> {
        self.virt_addr_region(offset, size)
            .ok_or(SvsmError::Mem)
            .and_then(|region| {
                if region.len() > buf.len() {
                    Err(SvsmError::Mem)
                } else {
                    // SAFETY: The region is valid and the buffer size is greater
                    // than or equal to the region size.
                    unsafe {
                        region
                            .start()
                            .as_ptr::<u8>()
                            .copy_to_nonoverlapping(buf.as_mut_ptr(), region.len())
                    };
                    Ok(())
                }
            })
    }

    /// Writes data from a provided buffer into a virtual address region specified by an offset
    /// and size.
    ///
    /// # Arguments
    ///
    /// * `offset`: The offset from the start of the virtual address region to write to.
    /// * `size`: The number of bytes to write.
    /// * `buf`: A reference to a byte array containing the data to write.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` that indicates the success or failure of the operation.
    /// If the write operation is successful, it returns `Ok(())`. If the virtual address region
    /// cannot be retrieved or if the buffer size is larger than the region size, it returns
    /// `Err(SvsmError::Mem)`.
    pub fn write(&self, offset: usize, size: usize, buf: &[u8]) -> Result<(), SvsmError> {
        self.virt_addr_region(offset, size)
            .ok_or(SvsmError::Mem)
            .and_then(|region| {
                if region.len() > buf.len() {
                    Err(SvsmError::Mem)
                } else {
                    // SAFETY: The region is valid and the buffer size is greater
                    // than or equal to the region size.
                    unsafe {
                        region
                            .start()
                            .as_mut_ptr::<u8>()
                            .copy_from_nonoverlapping(buf.as_ptr(), region.len())
                    };
                    Ok(())
                }
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
            .filter(|v| self.guard.mapping.contains_region(v))
        } else {
            None
        }
    }
}

impl InsnMachineMem for MemMappingGuard {
    fn read_integer(&self, offset: usize, size: Bytes) -> Result<u64, InsnError> {
        let mut buf = [0u8; 8];

        self.read(offset, size as usize, &mut buf)
            .map(|_| match size {
                Bytes::Zero => unreachable!("Unreachable for Zero size"),
                Bytes::One => buf[0] as u64,
                Bytes::Two => u16::from_ne_bytes([buf[0], buf[1]]) as u64,
                Bytes::Four => u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64,
                Bytes::Eight => u64::from_ne_bytes(buf),
            })
            .map_err(|_| InsnError::MemRead)
    }

    fn write_integer(&mut self, offset: usize, size: Bytes, data: u64) -> Result<(), InsnError> {
        match size {
            Bytes::Zero => return Err(InsnError::MemWrite),
            Bytes::One => self.write(offset, size as usize, (data as u8).to_ne_bytes().as_ref()),
            Bytes::Two => self.write(offset, size as usize, (data as u16).to_ne_bytes().as_ref()),
            Bytes::Four => self.write(offset, size as usize, (data as u32).to_ne_bytes().as_ref()),
            Bytes::Eight => self.write(offset, size as usize, data.to_ne_bytes().as_ref()),
        }
        .map_err(|_| InsnError::MemWrite)
    }
}
