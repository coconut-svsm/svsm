// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::virtualrange::VirtualRange;
use crate::mm::{SIZE_LEVEL1, SVSM_GLOBAL_MAPPING_BASE, SVSM_GLOBAL_MAPPING_END};
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::{align_up, MemoryRegion};

struct GlobalRanges {
    range_4k: VirtualRange,
    range_2m: VirtualRange,
}

impl GlobalRanges {
    const fn new() -> Self {
        Self {
            range_4k: VirtualRange::new(),
            range_2m: VirtualRange::new(),
        }
    }

    fn init(&mut self) {
        let region_4k_start = SVSM_GLOBAL_MAPPING_BASE;
        let region_2m_start = SVSM_GLOBAL_MAPPING_BASE + SIZE_LEVEL1;
        let page_count_4k = (region_2m_start - SVSM_GLOBAL_MAPPING_BASE) / PAGE_SIZE;
        let page_count_2m = (SVSM_GLOBAL_MAPPING_END - region_2m_start) / PAGE_SIZE_2M;

        self.range_4k
            .init(region_4k_start, page_count_4k, PAGE_SHIFT);
        self.range_2m
            .init(region_2m_start, page_count_2m, PAGE_SHIFT_2M);
    }

    fn alloc(
        &mut self,
        page_count: usize,
        huge: bool,
        shared: bool,
    ) -> Result<GlobalRangeGuard, SvsmError> {
        let vstart = if huge {
            self.range_2m.alloc(page_count, 0)?
        } else {
            self.range_4k.alloc(page_count, 0)?
        };

        Ok(GlobalRangeGuard::new(vstart, page_count, huge, shared))
    }

    fn free(&mut self, vaddr: VirtAddr, page_count: usize, huge: bool) {
        if huge {
            self.range_2m.free(vaddr, page_count);
        } else {
            self.range_4k.free(vaddr, page_count);
        }
    }
}

#[derive(Debug)]
pub struct GlobalRangeGuard {
    vstart: VirtAddr,
    pages: usize,
    huge: bool,
    shared: bool,
}

impl GlobalRangeGuard {
    /// Create a [`GlobalRangeGuard`] with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `vstart`: Start virtual address.
    /// * `pages`: Number pages mapped.
    /// * `huge`: Whether to use normal or huge pages.
    /// * `shared`: Whether mapping is private or shared.
    ///
    /// # Returns
    ///
    /// A new instance of [`GlobalRangeGuard`] set up with the requested
    /// parameters.
    fn new(vstart: VirtAddr, pages: usize, huge: bool, shared: bool) -> Self {
        Self {
            vstart,
            pages,
            huge,
            shared,
        }
    }

    /// Request the virtual start address of the global mapping.
    ///
    /// # Returns
    ///
    /// Virtual start address of the global mapping.
    pub fn addr(&self) -> VirtAddr {
        self.vstart
    }

    /// Request the length in bytes of the global mapping.
    ///
    /// # Returns
    ///
    /// Length of the global mapping in bytes.
    pub fn size(&self) -> usize {
        let page_size = if self.huge { PAGE_SIZE_2M } else { PAGE_SIZE };
        self.pages * page_size
    }

    fn map(&self, paddr: PhysAddr, flags: PTEntryFlags) -> Result<(), SvsmError> {
        if self.huge {
            this_cpu()
                .get_pgtable()
                .map_region_2m(self.region(), paddr, flags, self.shared)
        } else {
            this_cpu()
                .get_pgtable()
                .map_region_4k(self.region(), paddr, flags, self.shared)
        }
    }

    fn unmap(&self) {
        if self.huge {
            this_cpu().get_pgtable().unmap_region_2m(self.region());
        } else {
            this_cpu().get_pgtable().unmap_region_4k(self.region());
        }
    }

    /// Request the mapped region as a [`MemoryRegion`].
    ///
    /// # Returns
    ///
    /// The global mapped region as an instance of [`MemoryRegion`].
    pub fn region(&self) -> MemoryRegion<VirtAddr> {
        let page_size = if self.huge { PAGE_SIZE_2M } else { PAGE_SIZE };
        MemoryRegion::new(self.vstart, self.pages * page_size)
    }
}

impl Drop for GlobalRangeGuard {
    fn drop(&mut self) {
        self.unmap();
        // Flush TLB before allowing to re-use addresses
        flush_tlb_global_sync();
        GLOBAL_RANGES
            .lock()
            .free(self.vstart, self.pages, self.huge);
    }
}

static GLOBAL_RANGES: SpinLock<GlobalRanges> = SpinLock::new(GlobalRanges::new());

/// Initialize global allocatable virtual address ranges.
pub fn init_global_ranges() {
    GLOBAL_RANGES.lock().init();
}

/// Map physical addresses into the global shared address range.
///
/// # Arguments
///
/// * `pstart`: Start physical to map, must be aligned to requested page-size.
/// * `size`: Number of bytes to map. Will be aligned up to requested page-size.
/// * `flages`: Page-table flags to use for mapping.
/// * `huge`: Request normal or huge pages for the mapping.
/// * `shared`: Request a shared or private mapping.
///
/// # Returns
///
/// A Result with a [`GlobalRangeGuard`] on success or [`SvsmError`] on failure.
pub fn map_global_range(
    pstart: PhysAddr,
    size: usize,
    flags: PTEntryFlags,
    huge: bool,
    shared: bool,
) -> Result<GlobalRangeGuard, SvsmError> {
    assert!(pstart.is_page_aligned());

    let page_size = if huge { PAGE_SIZE_2M } else { PAGE_SIZE };
    let size_aligned = align_up(size, page_size);

    if size_aligned == 0 {
        return Err(SvsmError::Mem);
    }

    let pages = size_aligned / page_size;

    let guard = GLOBAL_RANGES.lock().alloc(pages, huge, shared)?;
    guard.map(pstart, flags)?;

    Ok(guard)
}

/// Create a private mapping using of physical addresses into the global shared
/// address range using 4KiB pages.
///
/// # Arguments
///
/// * `pstart`: Start physical to map, must be aligned to 4KiB.
/// * `size`: Number of bytes to map. Will be aligned up to 4KiB.
/// * `flages`: Page-table flags to use for mapping.
///
/// # Returns
///
/// A Result with a [`GlobalRangeGuard`] on success or [`SvsmError`] on failure.
pub fn map_global_range_4k_private(
    pstart: PhysAddr,
    size: usize,
    flags: PTEntryFlags,
) -> Result<GlobalRangeGuard, SvsmError> {
    map_global_range(pstart, size, flags, false, false)
}

/// Create a shared mapping using of physical addresses into the global shared
/// address range using 4KiB pages.
///
/// # Arguments
///
/// * `pstart`: Start physical to map, must be aligned to 4KiB.
/// * `size`: Number of bytes to map. Will be aligned up to 4KiB.
/// * `flages`: Page-table flags to use for mapping.
///
/// # Returns
///
/// A Result with a [`GlobalRangeGuard`] on success or [`SvsmError`] on failure.
pub fn map_global_range_4k_shared(
    pstart: PhysAddr,
    size: usize,
    flags: PTEntryFlags,
) -> Result<GlobalRangeGuard, SvsmError> {
    map_global_range(pstart, size, flags, false, true)
}

/// Create a private mapping using of physical addresses into the global shared
/// address range using 2MiB pages.
///
/// # Arguments
///
/// * `pstart`: Start physical to map, must be aligned to 2MiB.
/// * `size`: Number of bytes to map. Will be aligned up to 2MiB.
/// * `flages`: Page-table flags to use for mapping.
///
/// # Returns
///
/// A Result with a [`GlobalRangeGuard`] on success or [`SvsmError`] on failure.
pub fn map_global_range_2m_private(
    pstart: PhysAddr,
    size: usize,
    flags: PTEntryFlags,
) -> Result<GlobalRangeGuard, SvsmError> {
    map_global_range(pstart, size, flags, true, false)
}

/// Create a shared mapping using of physical addresses into the global shared
/// address range using 2MiB pages.
///
/// # Arguments
///
/// * `pstart`: Start physical to map, must be aligned to 2MiB.
/// * `size`: Number of bytes to map. Will be aligned up to 2MiB.
/// * `flages`: Page-table flags to use for mapping.
///
/// # Returns
///
/// A Result with a [`GlobalRangeGuard`] on success or [`SvsmError`] on failure.
pub fn map_global_range_2m_shared(
    pstart: PhysAddr,
    size: usize,
    flags: PTEntryFlags,
) -> Result<GlobalRangeGuard, SvsmError> {
    map_global_range(pstart, size, flags, true, true)
}
