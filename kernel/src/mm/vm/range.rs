// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::{flush_tlb_global_percpu_range, flush_tlb_global_sync_range};
use crate::error::SvsmError;
use crate::locking::RWLock;
use crate::mm::pagetable::{PTEntryFlags, PageTable, PageTablePart};
use crate::mm::virt_from_idx;
use crate::types::{PAGE_SHIFT, PAGE_SIZE, PageSize};
use crate::utils::MemoryRegion;
use crate::utils::unique_va_allocator::UniqueVaAllocator;

use core::borrow::Borrow;
use core::cmp::max;
use core::mem::ManuallyDrop;
use core::ops::Deref;

use super::Mapping;

extern crate alloc;
use alloc::vec::Vec;

/// Granularity of ranges mapped by [`struct VMR`]. The mapped region of a
/// [`struct VMR`] is always a multiple of this constant.
/// One [`VMR_GRANULE`] covers one top-level page-table entry on x86-64 with
/// 4-level paging.
pub const VMR_GRANULE: usize = PAGE_SIZE * 512 * 512 * 512;

/// Virtual Memory Region
///
/// This struct manages the mappings in a region of the virtual address space.
/// The region size is a multiple of 512GiB so that every region will fully
/// allocate one or more top-level page-table entries on x86-64. For the same
/// reason the start address must also be aligned to 512GB.
#[derive(Debug)]
pub struct VMR {
    /// Start address of this range as virtual PFN (VirtAddr >> PAGE_SHIFT).
    /// Virtual address must be aligned to [`VMR_GRANULE`] (512GB on x86-64).
    start_pfn: usize,

    /// End address of this range as virtual PFN (VirtAddr >> PAGE_SHIFT)
    /// Virtual address must be aligned to [`VMR_GRANULE`] (512GB on x86-64).
    end_pfn: usize,

    /// Allocator containing all mappings in the covered virtual address
    /// region, indexed by their start address.
    allocations: RWLock<UniqueVaAllocator<Mapping>>,

    /// [`struct PageTableParts`] needed to map this VMR into a page-table.
    /// There is one [`struct PageTablePart`] per [`VMR_GRANULE`] covered by
    /// the region.
    pgtbl_parts: RWLock<Vec<PageTablePart>>,

    /// [`PTEntryFlags`] global to all mappings in this region. This is a
    /// combination of [`PTEntryFlags::GLOBAL`] and [`PTEntryFlags::USER`].
    pt_flags: PTEntryFlags,

    /// Indicates that this [`struct VMR`] is visible only on a single CPU
    /// and therefore TLB flushes do not require broadcast.
    per_cpu: bool,
}

impl VMR {
    /// Creates a new [`struct VMR`]
    ///
    /// # Arguments
    ///
    /// * `start` - Virtual start address for the memory region. Must be aligned to [`VMR_GRANULE`]
    /// * `end` - Virtual end address (non-inclusive) for the memory region.
    ///   Must be bigger than `start` and aligned to [`VMR_GRANULE`].
    /// * `flags` - Global [`PTEntryFlags`] to use for this [`struct VMR`].
    ///
    /// # Returns
    ///
    /// A new instance of [`struct VMR`].
    pub fn new(start: VirtAddr, end: VirtAddr, flags: PTEntryFlags) -> Result<Self, SvsmError> {
        if start >= end || !start.is_aligned(VMR_GRANULE) || !end.is_aligned(VMR_GRANULE) {
            log::warn!("Attempted to create an invalid VMR {start:#018x}-{start:#018x}");
            return Err(SvsmError::Mem);
        }
        // Global and User are per VMR flags
        Ok(Self {
            start_pfn: start.pfn(),
            end_pfn: end.pfn(),
            allocations: RWLock::new(UniqueVaAllocator::new(start.as_usize(), end.as_usize())),
            pgtbl_parts: RWLock::new(Vec::new()),
            pt_flags: flags,
            per_cpu: false,
        })
    }

    /// Marks a [`struct VMR`] as being associated with only a single CPU
    /// so that TLB flushes do not require broadcast.
    pub fn set_per_cpu(&mut self, per_cpu: bool) {
        self.per_cpu = per_cpu;
    }

    /// Allocated all [`PageTablePart`]s needed to map this region
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, Err(SvsmError::Mem) on allocation error
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

    /// Populate [`PageTablePart`]s of the [`VMR`] into a page-table
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

    /// Initialize this [`VMR`] by calling `VMR::initialize_common` with `lazy = false`
    ///
    /// # Safety
    /// Callers must ensure that the bounds of the address range are
    /// appropriately aligned to prevent the possibility that adjacent address
    /// ranges may attempt to share top-level paging entries.  If any overlap
    /// is attempted, page tables may be corrupted.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, Err(SvsmError::Mem) on allocation error
    pub unsafe fn initialize(&self) -> Result<(), SvsmError> {
        self.alloc_page_tables(false)
    }

    /// Initialize this [`VMR`] by calling `VMR::initialize_common` with `lazy = true`
    ///
    /// # Safety
    /// Callers must ensure that the bounds of the address range are
    /// appropriately aligned to prevent the possibility that adjacent address
    /// ranges may attempt to share top-level paging entries.  If any overlap
    /// is attempted, page tables may be corrupted.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, Err(SvsmError::Mem) on allocation error
    pub unsafe fn initialize_lazy(&self) -> Result<(), SvsmError> {
        self.alloc_page_tables(true)
    }

    /// Returns the virtual start and end addresses for this region
    ///
    /// # Returns
    ///
    /// Tuple containing `start` and `end` virtual address of the memory region
    pub fn virt_range(&self) -> MemoryRegion<VirtAddr> {
        MemoryRegion::from_addresses(
            VirtAddr::from(self.start_pfn << PAGE_SHIFT),
            VirtAddr::from(self.end_pfn << PAGE_SHIFT),
        )
    }

    /// Map a [`Mapping`] into the [`PageTablePart`]s of this region
    ///
    /// # Arguments
    ///
    /// - `vaddr` - Virtual address at which to map `mapping`
    /// - `mapping` - Mapping to populate into the page-table
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, Err(SvsmError::Mem) on allocation error
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
                let pt_flags = self.pt_flags | mapping.pt_flags(offset) | PTEntryFlags::PRESENT;
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

    /// Unmap a [`Mapping`] from the [`PageTablePart`]s of this region
    ///
    /// # Arguments
    ///
    /// - `vaddr` - Virtual address at which `mapping` is mapped
    /// - `mapping` - Mapping to remove from the page-table
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

    fn finish_insert(
        &self,
        addr: usize,
        allocations: &mut UniqueVaAllocator<Mapping>,
    ) -> Result<VirtAddr, SvsmError> {
        let vaddr = VirtAddr::from(addr);
        let result = self.map_mapping(vaddr, allocations.get(addr).unwrap());
        if let Err(error) = result {
            self.unmap_mapping(vaddr, allocations.get(addr).unwrap());
            allocations.remove(addr);
            return Err(error);
        }

        Ok(vaddr)
    }

    /// Inserts a mapping at a specified virtual base address. This method
    /// checks that the mapping does not overlap with any other region.
    ///
    /// # Arguments
    ///
    /// * `vaddr` - Virtual base address at which to insert the mapping
    /// * `mapping` - Mapping to insert
    ///
    /// # Returns
    ///
    /// Base address where the mapping was inserted on success or
    /// `SvsmError::Mem` on error.
    pub fn insert_at(&self, vaddr: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let size = mapping.mapping_size();
        let mut allocations = self.allocations.lock_write();
        let addr = allocations
            .alloc_at(vaddr.as_usize(), size, mapping)
            .ok_or(SvsmError::Mem)?;
        self.finish_insert(addr, &mut allocations)
    }

    /// Inserts a mapping with the specified alignment. This method searches
    /// the allocator for a suitable region.
    ///
    /// # Arguments
    ///
    /// * `mapping` - Mapping to insert
    /// * `align` - Alignment to use for the mapping
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

        let size = mapping.mapping_size();
        let mut allocations = self.allocations.lock_write();
        let addr = allocations
            .alloc_aligned_hint(hint.as_usize(), size, align, mapping)
            .ok_or(SvsmError::Mem)?;
        self.finish_insert(addr, &mut allocations)
    }

    /// Inserts a mapping into the virtual memory region. This method takes the
    /// next power-of-two larger of the mapping size and uses that as the
    /// alignment for the mappings base address. The search for the base
    /// address starts at `addr`. With that it calls [`VMR::insert_aligned`].
    ///
    /// # Arguments
    ///
    /// * `addr` - The virtual address at which the search for a mapping area
    ///   starts
    /// * `mapping` - Mapping to insert
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

    /// Inserts a mapping into the virtual memory region. It searches from the
    /// beginning of the [`VMR`] region for a suitable slot.
    ///
    /// # Arguments
    ///
    /// * `mapping` - Mapping to insert
    ///
    /// # Returns
    ///
    /// Base address where the mapping was inserted on success or
    /// `SvsmError::Mem` on error.
    pub fn insert(&self, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        self.insert_hint(VirtAddr::new(0), mapping)
    }

    /// Removes the mapping at a given base address from the allocator.
    ///
    /// # Arguments
    ///
    /// * `base` - Virtual base address of the mapping to remove
    ///
    /// # Returns
    ///
    /// The removed mapping on success, SvsmError::Mem on error
    pub fn remove(&self, base: VirtAddr) -> Result<Mapping, SvsmError> {
        let mut allocations = self.allocations.lock_write();
        let mapping = allocations.remove(base.as_usize()).ok_or(SvsmError::Mem)?;
        self.unmap_mapping(base, &mapping);

        let region = MemoryRegion::new(base, mapping.mapping_size());
        let pgsize = mapping.page_size();

        if self.per_cpu {
            flush_tlb_global_percpu_range(region, pgsize);
        } else {
            flush_tlb_global_sync_range(region, pgsize);
        }

        Ok(mapping)
    }

    /// Dump all mappings in the allocator. This function is included for
    /// debugging purposes and should not be called in production code.
    pub fn dump_ranges(&self) {
        let allocations = self.allocations.lock_read();
        for (start, end, _) in allocations.iter() {
            log::info!("VMRange {start:#018x}-{end:#018x}");
        }
    }

    /// Handle a page fault for an address corresponding to this VMR.
    ///
    /// The fault is first handled by attemping to populate the provided page table
    /// with the page table parts corresponding to the faulting address. If that
    /// does not solve the fault, notify the backing mapping that a page fault has
    /// occurred.
    ///
    /// This should be called from the page fault handler. The mappings within this
    /// virtual memory region are examined and if they overlap with the page fault
    /// address then [`VirtualMapping::handle_page_fault`] is called to handle the
    /// page fault within that range.
    ///
    /// [`VirtualMapping::handle_page_fault`]: super::mapping::api::VirtualMapping::handle_page_fault
    ///
    /// # Arguments
    ///
    /// * `pgtable`: The page table to update with the faulted-in mapping, if applicable.
    /// * `vaddr` - Virtual memory address that was the subject of the page fault
    /// * 'write' - 'true' if a write was attempted. 'false' if a read was attempted.
    ///
    /// # Returns
    ///
    /// '()' if the page fault was successfully handled.
    ///
    /// 'SvsmError::Mem' if the page fault should propogate to the next handler.
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
        let allocations = self.allocations.lock_read();
        let (start, mapping) = allocations
            .get_containing(vaddr.as_usize())
            .ok_or(SvsmError::Mem)?;
        mapping.handle_page_fault(vaddr - VirtAddr::from(start), write)?;
        Ok(())
    }
}

/// A mapping in a [`VMR`], holding a reference `V` to that `VMR`.
/// The mapping is torn down on drop.
#[derive(Debug)]
pub struct VMRMapping<V: Borrow<VMR>> {
    vmr: V,
    va: VirtAddr,
}

impl<V: Borrow<VMR>> VMRMapping<V> {
    pub fn new(vmr: V, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert(mapping)?;
        Ok(Self { vmr, va })
    }

    pub fn new_at(vmr: V, addr: VirtAddr, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert_at(addr, mapping)?;
        Ok(Self { vmr, va })
    }

    pub fn new_hint(vmr: V, addr: VirtAddr, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert_hint(addr, mapping)?;
        Ok(Self { vmr, va })
    }

    pub fn leak(self) -> VirtAddr {
        let md = ManuallyDrop::new(self);
        md.va
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.va
    }
}

impl<V: Borrow<VMR>> Deref for VMRMapping<V> {
    type Target = VirtAddr;

    fn deref(&self) -> &VirtAddr {
        &self.va
    }
}

impl<V: Borrow<VMR>> Drop for VMRMapping<V> {
    fn drop(&mut self) {
        self.vmr
            .borrow()
            .remove(self.va)
            .expect("Error removing VRMapping virtual memory range");
    }
}

#[cfg(test)]
mod tests {
    use super::{VMR, VMR_GRANULE};
    use crate::address::VirtAddr;
    use crate::mm::pagetable::PTEntryFlags;
    use crate::mm::vm::VMReserved;
    use crate::types::PAGE_SIZE;

    fn new_vmr() -> VMR {
        VMR::new(
            VirtAddr::from(VMR_GRANULE),
            VirtAddr::from(2 * VMR_GRANULE),
            PTEntryFlags::empty(),
        )
        .unwrap()
    }

    #[test]
    fn fixed_insert_rejects_invalid_ranges() {
        let vmr = new_vmr();
        let base = VirtAddr::from(VMR_GRANULE);

        assert!(
            vmr.insert_at(base, VMReserved::new_mapping(PAGE_SIZE))
                .is_ok()
        );
        assert!(
            vmr.insert_at(base, VMReserved::new_mapping(PAGE_SIZE))
                .is_err()
        );
        assert!(
            vmr.insert_at(base + 1, VMReserved::new_mapping(PAGE_SIZE))
                .is_err()
        );
        assert!(
            vmr.insert_at(
                VirtAddr::from(2 * VMR_GRANULE),
                VMReserved::new_mapping(PAGE_SIZE),
            )
            .is_err()
        );
    }

    #[test]
    fn non_power_of_two_mapping_does_not_reserve_padding() {
        let vmr = new_vmr();
        let base = vmr.insert(VMReserved::new_mapping(3 * PAGE_SIZE)).unwrap();

        assert_eq!(base, VirtAddr::from(VMR_GRANULE));
        assert_eq!(
            vmr.insert(VMReserved::new_mapping(PAGE_SIZE)).unwrap(),
            base + 3 * PAGE_SIZE
        );
    }
}
