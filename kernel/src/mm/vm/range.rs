// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::cpu::{flush_tlb_global_percpu_range, flush_tlb_global_sync_range};
use crate::error::SvsmError;
use crate::locking::RWLock;
use crate::mm::pagetable::{PTEntryFlags, PageTable, PageTablePart};
use crate::mm::{AddrSpaceDescriptor, virt_from_idx};
use crate::types::{PAGE_SIZE, PageSize};
use crate::utils::MemoryRegion;
use crate::utils::unique_va_allocator::UniqueVaAllocator;

use core::borrow::Borrow;
use core::cmp::max;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::Deref;

use super::Mapping;

extern crate alloc;
use alloc::vec::Vec;

/// Granularity of ranges mapped by [`Vmr`]. The mapped region of a [`Vmr`] is
/// always a multiple of this constant. One [`VMR_GRANULE`] covers one top-level
/// page-table entry on x86-64 with 4-level paging.
pub const VMR_GRANULE: usize = PAGE_SIZE * 512 * 512 * 512;

/// A statically-described virtual memory range.
///
/// A [`VmRange`] associates a fixed region of the virtual address space with
/// the allocator that hands out virtual addresses within it, together with the
/// page-table properties shared by all of those mappings.
pub trait VmRange: Sized + Sync + core::fmt::Debug {
    /// The region of the virtual address space covered by this range.
    const DESCRIPTOR: AddrSpaceDescriptor;

    /// Page-table flags applied to every mapping in this range.
    const PT_FLAGS: PTEntryFlags;

    /// Whether mappings in this range are per-CPU. This selects the TLB
    /// flushing behaviour used when mappings are removed.
    const PER_CPU: bool = false;

    /// The allocator that reserves and tracks the [`Mapping`]s of this range.
    type Allocator: VmAllocator<Self>;
}

/// An allocator of [`Mapping`]s within a [`VmRange`].
///
/// Implementations reserve virtual address ranges, associate a [`Mapping`]
/// with each reservation, and answer the reverse lookup used to resolve page
/// faults.
pub trait VmAllocator<V: VmRange>: Sync + core::fmt::Debug {
    /// Creates an allocator managing the region for `V::DESCRIPTOR`.
    fn new() -> Self;

    /// Reserves `size` bytes at or above `hint`, aligned to `align`, and
    /// associates `mapping` with the reservation.
    ///
    /// Returns the base address of the reservation.
    fn alloc(
        &self,
        hint: VirtAddr,
        size: usize,
        align: usize,
        mapping: Mapping,
    ) -> Result<VirtAddr, SvsmError>;

    /// Reserves exactly `size` bytes at `at` and associates `mapping` with the
    /// reservation.
    fn alloc_at(&self, at: VirtAddr, size: usize, mapping: Mapping) -> Result<VirtAddr, SvsmError>;

    /// Removes the mapping at `base` and returns it.
    ///
    /// This allows implementing allocators where teardown involves a two
    /// step atomic transaction: the mapping is verified to be present and
    /// locked down, then torn down (e.g. removed from page tables), and
    /// finally marked as free in allocator itself.
    ///
    /// Returns `None` if there is no mapping at `base`, in which case
    /// `teardown` is not invoked.
    fn free<F>(&self, base: VirtAddr, teardown: F) -> Option<Mapping>
    where
        F: FnOnce(&Mapping);

    /// Returns the base address and [`Mapping`] of the reservation containing
    /// `addr`, as visible to this allocator instance.
    fn query(&self, addr: VirtAddr) -> Option<(VirtAddr, Mapping)>;

    /// Invokes `f` for each allocation owned by the allocator
    fn for_each<F>(&self, f: F)
    where
        F: FnMut(VirtAddr, &Mapping);
}

/// A per-instance [`VmAllocator`] backed by a [`UniqueVaAllocator`].
///
/// The reservation authority and the [`Mapping`] store are the same
/// structure, so every mapped address is tracked in exactly one place.
#[derive(Debug)]
pub struct PrivateVmAllocator<V: VmRange> {
    allocations: RWLock<UniqueVaAllocator<Mapping>>,
    _phantom: PhantomData<V>,
}

impl<V: VmRange> VmAllocator<V> for PrivateVmAllocator<V> {
    fn new() -> Self {
        Self {
            allocations: RWLock::new(UniqueVaAllocator::new(
                V::DESCRIPTOR.base().as_usize(),
                V::DESCRIPTOR.end().as_usize(),
            )),
            _phantom: PhantomData,
        }
    }

    fn alloc(
        &self,
        hint: VirtAddr,
        size: usize,
        align: usize,
        mapping: Mapping,
    ) -> Result<VirtAddr, SvsmError> {
        self.allocations
            .lock_write()
            .alloc_aligned_hint(hint.as_usize(), size, align, mapping)
            .map(VirtAddr::from)
            .ok_or(SvsmError::Mem)
    }

    fn alloc_at(&self, at: VirtAddr, size: usize, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        self.allocations
            .lock_write()
            .alloc_at(at.as_usize(), size, mapping)
            .map(VirtAddr::from)
            .ok_or(SvsmError::Mem)
    }

    fn free<F>(&self, base: VirtAddr, teardown: F) -> Option<Mapping>
    where
        F: FnOnce(&Mapping),
    {
        // Hold the allocator lock across the teardown. This prevents concurrent
        // double frees, and handing out the original allocation while teardown
        // is in progress.
        let mut guard = self.allocations.lock_write();
        let mapping = guard.remove(base.as_usize())?;
        teardown(&mapping);
        Some(mapping)
    }

    fn query(&self, addr: VirtAddr) -> Option<(VirtAddr, Mapping)> {
        self.allocations
            .lock_read()
            .get_containing(addr.as_usize())
            .map(|(base, mapping)| (VirtAddr::from(base), mapping.clone()))
    }

    fn for_each<F: FnMut(VirtAddr, &Mapping)>(&self, mut f: F) {
        for (start, _, m) in self.allocations.lock_read().iter() {
            f(VirtAddr::from(start), m);
        }
    }
}

/// A statically-described virtual memory range.
///
/// A [`Vmr`] manages the mappings of a region of the virtual address space.
/// The covered region, its page-table flags and its per-CPU property are
/// provided by the [`VmRange`] type parameter, and mappings are reserved and
/// tracked by its [`VmRange::Allocator`].
#[derive(Debug)]
pub struct Vmr<V: VmRange> {
    /// Allocator reserving and tracking the [`Mapping`]s of this region.
    alloc: V::Allocator,

    /// [`PageTablePart`]s needed to map this region into a page-table. There
    /// is one [`PageTablePart`] per [`VMR_GRANULE`] covered by the region.
    pgtbl_parts: RWLock<Vec<PageTablePart>>,
}

impl<V: VmRange> Vmr<V> {
    /// Creates a new [`Vmr`] for the region described by `V`.
    pub fn new() -> Self {
        const {
            let desc = V::DESCRIPTOR;
            assert!(desc.size() > 0 && desc.size() % VMR_GRANULE == 0);
            assert!(desc.base().as_usize() & (VMR_GRANULE - 1) == 0);
        }
        Self {
            alloc: V::Allocator::new(),
            pgtbl_parts: RWLock::new(Vec::new()),
        }
    }

    /// Returns the virtual region covered by this range.
    pub fn virt_range(&self) -> MemoryRegion<VirtAddr> {
        V::DESCRIPTOR.region()
    }

    /// Allocates all [`PageTablePart`]s needed to map this region.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(SvsmError::Mem)` on allocation error
    fn alloc_page_tables(&self, lazy: bool) -> Result<(), SvsmError> {
        let vregion = self.virt_range();

        let first_idx = vregion.start().to_pgtbl_idx::<3>();
        let start = virt_from_idx(first_idx);
        let last_idx = (vregion.end() - 1).to_pgtbl_idx::<3>();
        let count = last_idx + 1 - first_idx;
        let mut vec = self.pgtbl_parts.lock_write();

        for idx in 0..count {
            let mut part = PageTablePart::new(start + (idx * VMR_GRANULE));
            if !lazy {
                part.alloc();
            }
            vec.push(part);
        }

        Ok(())
    }

    /// Populate the [`PageTablePart`]s of this region into a page-table.
    ///
    /// # Arguments
    ///
    /// * `pgtbl` - A [`PageTable`] pointing to the target page-table
    pub fn populate(&self, pgtbl: &mut PageTable) {
        let parts = self.pgtbl_parts.lock_read();

        for part in parts.iter() {
            pgtbl.populate_pgtbl_part(part);
        }
    }

    fn populate_addr(&self, pgtbl: &mut PageTable, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let vregion = self.virt_range();
        if !vregion.contains(vaddr) {
            return Err(SvsmError::Mem);
        }

        let idx = vaddr.to_pgtbl_idx::<3>() - vregion.start().to_pgtbl_idx::<3>();
        let parts = self.pgtbl_parts.lock_read();
        if !pgtbl.populate_pgtbl_part(&parts[idx]) {
            return Err(SvsmError::Mem);
        }
        Ok(())
    }

    /// Allocate all [`PageTablePart`]s of this region eagerly.
    ///
    /// `Ok(())` on success, `Err(SvsmError::Mem)` on allocation error
    pub fn initialize(&self) -> Result<(), SvsmError> {
        self.alloc_page_tables(false)
    }

    /// Allocate the [`PageTablePart`]s of this region lazily.
    ///
    /// `Ok(())` on success, `Err(SvsmError::Mem)` on allocation error
    pub fn initialize_lazy(&self) -> Result<(), SvsmError> {
        self.alloc_page_tables(true)
    }

    /// Map a [`Mapping`] into the [`PageTablePart`]s of this region.
    fn map_mapping(&self, vaddr: VirtAddr, mapping: &Mapping) -> Result<(), SvsmError> {
        let rstart = self.virt_range().start();
        let mapping_end = vaddr + mapping.mapping_size();
        let mut pgtbl_parts = self.pgtbl_parts.lock_write();
        let mut offset: usize = 0;
        let page_size = mapping.page_size();
        let shared = mapping.shared();

        // Exit early if the mapping has no data.
        if !mapping.has_data() {
            return Ok(());
        }

        while vaddr + offset < mapping_end {
            let idx = PageTable::index::<3>(VirtAddr::from(vaddr - rstart));
            if let Some(paddr) = mapping.map(offset) {
                let pt_flags = V::PT_FLAGS | mapping.pt_flags(offset) | PTEntryFlags::PRESENT;
                match page_size {
                    PageSize::Regular => {
                        pgtbl_parts[idx].map_4k(vaddr + offset, paddr, pt_flags, shared)?
                    }
                    PageSize::Huge => {
                        pgtbl_parts[idx].map_2m(vaddr + offset, paddr, pt_flags, shared)?
                    }
                }
            }
            offset += usize::from(page_size);
        }

        Ok(())
    }

    /// Unmap a [`Mapping`] from the [`PageTablePart`]s of this region.
    fn unmap_mapping(&self, vaddr: VirtAddr, mapping: &Mapping) {
        if !mapping.has_data() {
            return;
        }

        let rstart = self.virt_range().start();
        let mapping_end = vaddr + mapping.mapping_size();
        let mut pgtbl_parts = self.pgtbl_parts.lock_write();
        let page_size = mapping.page_size();
        let mut offset: usize = 0;

        while vaddr + offset < mapping_end {
            let idx = PageTable::index::<3>(VirtAddr::from(vaddr - rstart));
            let result = match page_size {
                PageSize::Regular => pgtbl_parts[idx].unmap_4k(vaddr + offset),
                PageSize::Huge => pgtbl_parts[idx].unmap_2m(vaddr + offset),
            };

            if result.is_some() {
                mapping.unmap(offset);
            }

            offset += usize::from(page_size);
        }
    }

    /// Map a reserved mapping into the page-table, undoing the reservation on
    /// failure.
    fn finish_insert(&self, base: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        if let Err(error) = self.map_mapping(base, &mapping) {
            self.alloc
                .free(base, |mapping| self.unmap_mapping(base, mapping));
            return Err(error);
        }

        Ok(base)
    }

    /// Inserts a mapping at a specified virtual base address. This method
    /// checks that the mapping does not overlap with any other region.
    ///
    /// # Returns
    ///
    /// Base address where the mapping was inserted on success or
    /// `SvsmError::Mem` on error.
    pub fn insert_at(&self, vaddr: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let base = self
            .alloc
            .alloc_at(vaddr, mapping.mapping_size(), mapping.clone())?;
        self.finish_insert(base, mapping)
    }

    /// Inserts a mapping with the specified alignment, searching at or above
    /// `hint`.
    ///
    /// # Returns
    ///
    /// Base address where the mapping was inserted on success or
    /// `SvsmError::Mem` on error.
    pub fn insert_aligned(
        &self,
        hint: VirtAddr,
        mapping: Mapping,
        align: usize,
    ) -> Result<VirtAddr, SvsmError> {
        assert!(align.is_power_of_two());
        assert!(align >= PAGE_SIZE);

        let base = self
            .alloc
            .alloc(hint, mapping.mapping_size(), align, mapping.clone())?;
        self.finish_insert(base, mapping)
    }

    /// Inserts a mapping, using the next power-of-two of its size as alignment
    /// and starting the search at `addr`.
    ///
    /// # Returns
    ///
    /// Base address where the mapping was inserted on success or
    /// `SvsmError::Mem` on error.
    pub fn insert_hint(&self, addr: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let align = max(
            mapping
                .mapping_size()
                .checked_next_power_of_two()
                .ok_or(SvsmError::Mem)?,
            PAGE_SIZE,
        );
        self.insert_aligned(addr, mapping, align)
    }

    /// Inserts a mapping, searching from the beginning of the region.
    ///
    /// # Returns
    ///
    /// Base address where the mapping was inserted on success or
    /// `SvsmError::Mem` on error.
    pub fn insert(&self, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        self.insert_hint(VirtAddr::new(0), mapping)
    }

    /// Removes the mapping at a given base address.
    ///
    /// # Returns
    ///
    /// The removed mapping on success, `SvsmError::Mem` on error
    pub fn remove(&self, base: VirtAddr) -> Result<Mapping, SvsmError> {
        self.alloc
            .free(base, |mapping| {
                // Remove the mapping from the page tables and flush the TLB
                // before giving out the address range back to the allocator.
                self.unmap_mapping(base, mapping);
                let region = MemoryRegion::new(base, mapping.mapping_size());
                let pgsize = mapping.page_size();
                if V::PER_CPU {
                    flush_tlb_global_percpu_range(region, pgsize);
                } else {
                    flush_tlb_global_sync_range(region, pgsize);
                }
            })
            .ok_or(SvsmError::Mem)
    }

    /// Dump all mappings in this range. This function is included for
    /// debugging purposes and should not be called in production code.
    pub fn dump_ranges(&self) {
        self.alloc.for_each(|start, m| {
            let end = start + m.mapping_size();
            log::info!("VMRange {start:#018x}-{end:#018x}");
        });
    }

    /// Handle a page fault for an address corresponding to this range.
    ///
    /// The fault is first handled by attempting to populate the provided page
    /// table with the page-table parts corresponding to the faulting address.
    /// If that does not solve the fault, the backing mapping is notified.
    ///
    /// # Arguments
    ///
    /// * `pgtable`: The page table to update with the faulted-in mapping, if
    ///   applicable.
    /// * `vaddr` - Virtual memory address that was the subject of the page fault
    /// * `write` - `true` if a write was attempted, `false` if a read.
    ///
    /// # Returns
    ///
    /// `()` if the page fault was successfully handled, `SvsmError::Mem` if it
    /// should propagate to the next handler.
    pub fn handle_page_fault(
        &self,
        pgtable: &mut PageTable,
        vaddr: VirtAddr,
        write: bool,
    ) -> Result<(), SvsmError> {
        // Check first if the fault is solved by populating the page table
        if let Ok(()) = self.populate_addr(pgtable, vaddr) {
            return Ok(());
        }

        // Get the mapping that contains the faulting address and check if the
        // fault happened on a mapped part of the range.
        let (start, mapping) = self.alloc.query(vaddr).ok_or(SvsmError::Mem)?;
        mapping.handle_page_fault(vaddr - start, write)?;
        Ok(())
    }
}

/// A mapping in a [`Vmr`], holding a reference `B` to that range.
/// The mapping is torn down on drop.
#[derive(Debug)]
pub struct VmrMapping<V: VmRange, B: Borrow<Vmr<V>>> {
    vmr: B,
    va: VirtAddr,
    _range: PhantomData<V>,
}

impl<V: VmRange, B: Borrow<Vmr<V>>> VmrMapping<V, B> {
    pub fn new(vmr: B, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert(mapping)?;
        Ok(Self {
            vmr,
            va,
            _range: PhantomData,
        })
    }

    pub fn new_at(vmr: B, addr: VirtAddr, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert_at(addr, mapping)?;
        Ok(Self {
            vmr,
            va,
            _range: PhantomData,
        })
    }

    pub fn new_hint(vmr: B, addr: VirtAddr, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert_hint(addr, mapping)?;
        Ok(Self {
            vmr,
            va,
            _range: PhantomData,
        })
    }

    pub fn leak(self) -> VirtAddr {
        let md = ManuallyDrop::new(self);
        md.va
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.va
    }
}

impl<V: VmRange, B: Borrow<Vmr<V>>> Deref for VmrMapping<V, B> {
    type Target = VirtAddr;

    fn deref(&self) -> &VirtAddr {
        &self.va
    }
}

impl<V: VmRange, B: Borrow<Vmr<V>>> Drop for VmrMapping<V, B> {
    fn drop(&mut self) {
        self.vmr
            .borrow()
            .remove(self.va)
            .expect("Error removing VmrMapping virtual memory range");
    }
}
