// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::flush_tlb_global_sync_range;
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::locking::{RawLockGuard, SpinLock};
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::virtualrange::{SubVmAlloc, SubVmAllocator, SubVmRange};
use crate::mm::{AddrSpaceDescriptor, GLOBAL_MAPPING_2M, GLOBAL_MAPPING_4K};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M, PageSize};
use crate::utils::{MemoryRegion, align_up};

#[derive(Debug)]
struct GlobalRange4k;

impl SubVmRange for GlobalRange4k {
    const DESCRIPTOR: AddrSpaceDescriptor = GLOBAL_MAPPING_4K;
    const GRANULE: usize = PAGE_SIZE;

    fn get_allocator() -> impl core::ops::DerefMut<Target = SubVmAllocator<Self>> {
        RawLockGuard::map(GLOBAL_RANGES.lock(), |r| &mut r.range_4k)
    }
}

#[derive(Debug)]
struct GlobalRange2m;

impl SubVmRange for GlobalRange2m {
    const DESCRIPTOR: AddrSpaceDescriptor = GLOBAL_MAPPING_2M;
    const GRANULE: usize = PAGE_SIZE_2M;

    fn get_allocator() -> impl core::ops::DerefMut<Target = SubVmAllocator<Self>> {
        RawLockGuard::map(GLOBAL_RANGES.lock(), |r| &mut r.range_2m)
    }
}

#[derive(Debug)]
enum GlobalRangeAlloc {
    Regular(SubVmAlloc<GlobalRange4k>),
    Huge(SubVmAlloc<GlobalRange2m>),
}

impl GlobalRangeAlloc {
    const fn region(&self) -> MemoryRegion<VirtAddr> {
        match self {
            Self::Regular(r) => r.region(),
            Self::Huge(r) => r.region(),
        }
    }

    const fn huge(&self) -> bool {
        matches!(self, Self::Huge(..))
    }
}

struct GlobalRanges {
    range_4k: SubVmAllocator<GlobalRange4k>,
    range_2m: SubVmAllocator<GlobalRange2m>,
}

impl GlobalRanges {
    const fn new() -> Self {
        Self {
            range_4k: SubVmAllocator::new(),
            range_2m: SubVmAllocator::new(),
        }
    }

    fn init(&mut self) {
        self.range_4k.init();
        self.range_2m.init();
    }
}

#[derive(Debug)]
pub struct GlobalRangeGuard {
    range: GlobalRangeAlloc,
}

impl GlobalRangeGuard {
    /// Create a [`GlobalRangeGuard`] with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `paddr`: Start physical address.
    /// * `pages`: Number pages mapped.
    /// * `flags`: Page-table flags to use for mapping.
    /// * `huge`: Whether to use normal or huge pages.
    /// * `shared`: Whether mapping is private or shared.
    ///
    /// # Returns
    ///
    /// A new instance of [`GlobalRangeGuard`] set up with the requested
    /// parameters.
    fn new(
        paddr: PhysAddr,
        pages: usize,
        flags: PTEntryFlags,
        huge: bool,
        shared: bool,
    ) -> Result<Self, SvsmError> {
        let range = if huge {
            let range = SubVmAlloc::new(pages, 0)?;
            this_cpu()
                .get_pgtable()
                .map_region_2m(range.region(), paddr, flags, shared)?;
            GlobalRangeAlloc::Huge(range)
        } else {
            let range = SubVmAlloc::new(pages, 0)?;
            this_cpu()
                .get_pgtable()
                .map_region_4k(range.region(), paddr, flags, shared)?;
            GlobalRangeAlloc::Regular(range)
        };
        Ok(Self { range })
    }

    /// Request the virtual start address of the global mapping.
    ///
    /// # Returns
    ///
    /// Virtual start address of the global mapping.
    pub fn addr(&self) -> VirtAddr {
        self.region().start()
    }

    /// Request the length in bytes of the global mapping.
    ///
    /// # Returns
    ///
    /// Length of the global mapping in bytes.
    pub fn size(&self) -> usize {
        self.region().len()
    }

    /// Request the mapped region as a [`MemoryRegion`].
    ///
    /// # Returns
    ///
    /// The global mapped region as an instance of [`MemoryRegion`].
    pub fn region(&self) -> MemoryRegion<VirtAddr> {
        self.range.region()
    }
}

impl Drop for GlobalRangeGuard {
    fn drop(&mut self) {
        let pgsize = if self.range.huge() {
            this_cpu().get_pgtable().unmap_region_2m(self.region());
            PageSize::Huge
        } else {
            this_cpu().get_pgtable().unmap_region_4k(self.region());
            PageSize::Regular
        };
        // Flush TLB before allowing to re-use addresses
        flush_tlb_global_sync_range(self.region(), pgsize);
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

    GlobalRangeGuard::new(pstart, pages, flags, huge, shared)
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
