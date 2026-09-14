// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Advanced Micro Devices, Inc.
//
// Author: Joerg Roedel <joerg.roedel@amd.com>

//! Context-specific virtual memory ranges.

use super::{Mapping, VMM, VMMAdapter};
use crate::address::{Address, VirtAddr};
use crate::cpu::flush_tlb_global_sync_range;
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use crate::mm::pagetable::{PTEntryFlags, PageTable, PageTablePart};
use crate::mm::{SVSM_PERTASK_BASE, SVSM_PERTASK_END};
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use crate::utils::unique_va_allocator::UniqueVaAllocator;

use core::borrow::Borrow;
use core::cell::Cell;
use core::mem::ManuallyDrop;
use core::ops::Deref;

use intrusive_collections::Bound;
use intrusive_collections::rbtree::RBTree;

extern crate alloc;
use alloc::boxed::Box;

/// The shared allocator for globally unique context virtual addresses.
#[derive(Debug)]
struct ContextVMRAllocator {
    ranges: SpinLock<UniqueVaAllocator<ContextVMRAllocation>>,
}

#[derive(Debug)]
struct ContextVMRAllocation {
    shareable: bool,
    refcount: Cell<usize>,
    mapping: Option<Mapping>,
}

impl ContextVMRAllocation {
    const fn private() -> Self {
        Self {
            shareable: false,
            refcount: Cell::new(1),
            mapping: None,
        }
    }

    fn shared(mapping: Mapping) -> Self {
        Self {
            shareable: true,
            refcount: Cell::new(1),
            mapping: Some(mapping),
        }
    }
}

impl ContextVMRAllocator {
    const fn new() -> Self {
        Self {
            ranges: SpinLock::new(UniqueVaAllocator::new(
                SVSM_PERTASK_BASE.as_usize(),
                SVSM_PERTASK_END.as_usize(),
            )),
        }
    }

    fn alloc_aligned(&self, hint: VirtAddr, size: usize, align: usize) -> Option<VirtAddr> {
        self.ranges
            .lock()
            .alloc_aligned_hint(
                hint.as_usize(),
                size,
                align,
                ContextVMRAllocation::private(),
            )
            .map(VirtAddr::from)
    }

    fn alloc_at(&self, addr: VirtAddr, size: usize) -> Option<VirtAddr> {
        self.ranges
            .lock()
            .alloc_at(addr.as_usize(), size, ContextVMRAllocation::private())
            .map(VirtAddr::from)
    }

    fn alloc_shared(&self, mapping: Mapping) -> Option<VirtAddr> {
        let size = mapping.mapping_size();
        let allocation = ContextVMRAllocation::shared(mapping);

        self.ranges
            .lock()
            .alloc(size, allocation)
            .map(VirtAddr::from)
    }

    fn map_shared(&self, addr: VirtAddr) -> Option<Mapping> {
        let ranges = self.ranges.lock();
        let allocation = ranges.get(addr.as_usize())?;

        if !allocation.shareable {
            return None;
        }

        let mapping = allocation.mapping.clone()?;
        allocation
            .refcount
            .set(allocation.refcount.get().checked_add(1)?);
        Some(mapping)
    }

    fn free(&self, addr: VirtAddr) {
        let mut ranges = self.ranges.lock();
        let Some(allocation) = ranges.get(addr.as_usize()) else {
            return;
        };

        if allocation.shareable {
            let refcount = allocation
                .refcount
                .get()
                .checked_sub(1)
                .expect("ContextVMR allocation refcount underflow");
            allocation.refcount.set(refcount);
            if refcount != 0 {
                return;
            }
        }

        ranges.free(addr.as_usize());
    }
}

static CONTEXT_VMR_ALLOCATOR: ContextVMRAllocator = ContextVMRAllocator::new();

/// A virtual memory range with globally unique, context-specific mappings.
///
/// All [`ContextVMR`] instances allocate from one shared address allocator, but
/// each instance owns a separate [`PageTablePart`]. Consequently, mappings
/// have unique virtual addresses by default while remaining visible only in
/// page tables populated from the owning [`ContextVMR`]. Mappings created with
/// [`ContextVMR::alloc_shared`] may be installed in multiple instances at the
/// same virtual address.
#[derive(Debug)]
pub struct ContextVMR {
    tree: RWLock<RBTree<VMMAdapter>>,
    pgtbl_part: RWLock<PageTablePart>,
    pt_flags: PTEntryFlags,
}

impl ContextVMR {
    /// Creates an empty context-specific virtual memory range.
    pub fn new(flags: PTEntryFlags) -> Self {
        Self {
            tree: RWLock::new(RBTree::new(VMMAdapter::new())),
            pgtbl_part: RWLock::new(PageTablePart::new(SVSM_PERTASK_BASE)),
            pt_flags: flags,
        }
    }

    /// Allocates the root page for this range's page-table subtree.
    pub fn initialize(&self) {
        self.pgtbl_part.lock_write().alloc();
    }

    /// Populates this range's page-table subtree into `pgtbl`.
    pub fn populate(&self, pgtbl: &mut PageTable) {
        pgtbl.populate_pgtbl_part(&self.pgtbl_part.lock_read());
    }

    /// Returns the complete address region managed by all [`ContextVMR`]
    /// instances.
    pub fn virt_range(&self) -> MemoryRegion<VirtAddr> {
        MemoryRegion::from_addresses(SVSM_PERTASK_BASE, SVSM_PERTASK_END)
    }

    fn map_vmm(&self, vmm: &VMM) -> Result<(), SvsmError> {
        let (start, end) = vmm.range();
        let mapping = vmm.get_mapping();
        let mut pgtbl_part = self.pgtbl_part.lock_write();
        let page_size = mapping.page_size();
        let shared = mapping.shared();
        let mut offset = 0;

        if !mapping.has_data() {
            return Ok(());
        }

        while start + offset < end {
            if let Some(paddr) = mapping.map(offset) {
                let flags = self.pt_flags | mapping.pt_flags(offset) | PTEntryFlags::PRESENT;
                match page_size {
                    PageSize::Regular => pgtbl_part.map_4k(start + offset, paddr, flags, shared)?,
                    PageSize::Huge => pgtbl_part.map_2m(start + offset, paddr, flags, shared)?,
                }
            }
            offset += usize::from(page_size);
        }

        Ok(())
    }

    fn unmap_vmm(&self, vmm: &VMM) {
        let (start, end) = vmm.range();
        let mapping = vmm.get_mapping();

        if !mapping.has_data() {
            return;
        }

        let mut pgtbl_part = self.pgtbl_part.lock_write();
        let page_size = mapping.page_size();
        let mut offset = 0;

        while start + offset < end {
            let result = match page_size {
                PageSize::Regular => pgtbl_part.unmap_4k(start + offset),
                PageSize::Huge => pgtbl_part.unmap_2m(start + offset),
            };

            if result.is_some() {
                mapping.unmap(offset);
            }
            offset += usize::from(page_size);
        }
    }

    fn insert_allocated(&self, addr: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let vmm = Box::new(VMM::new(addr.pfn(), mapping));
        let mut tree = self.tree.lock_write();

        if !tree.find(&addr.pfn()).is_null() {
            CONTEXT_VMR_ALLOCATOR.free(addr);
            return Err(SvsmError::Mem);
        }

        if let Err(error) = self.map_vmm(&vmm) {
            self.unmap_vmm(&vmm);
            CONTEXT_VMR_ALLOCATOR.free(addr);
            return Err(error);
        }

        tree.insert(vmm);
        Ok(addr)
    }

    /// Allocates a mapping which may be mapped into other [`ContextVMR`]
    /// instances.
    pub fn alloc_shared(&self, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let addr = CONTEXT_VMR_ALLOCATOR
            .alloc_shared(mapping.clone())
            .ok_or(SvsmError::Mem)?;
        self.insert_allocated(addr, mapping)
    }

    /// Maps a shared allocation into this [`ContextVMR`].
    pub fn map_shared(&self, addr: VirtAddr) -> Result<VirtAddr, SvsmError> {
        let mapping = CONTEXT_VMR_ALLOCATOR
            .map_shared(addr)
            .ok_or(SvsmError::Mem)?;
        self.insert_allocated(addr, mapping)
    }

    /// Inserts a mapping at an exact virtual address.
    pub fn insert_at(&self, addr: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let addr = CONTEXT_VMR_ALLOCATOR
            .alloc_at(addr, mapping.mapping_size())
            .ok_or(SvsmError::Mem)?;
        self.insert_allocated(addr, mapping)
    }

    /// Inserts a mapping at or above `hint` with the requested alignment.
    pub fn insert_aligned(
        &self,
        hint: VirtAddr,
        mapping: Mapping,
        align: usize,
    ) -> Result<VirtAddr, SvsmError> {
        let addr = CONTEXT_VMR_ALLOCATOR
            .alloc_aligned(hint, mapping.mapping_size(), align)
            .ok_or(SvsmError::Mem)?;
        self.insert_allocated(addr, mapping)
    }

    /// Inserts a naturally aligned mapping at or above `hint`.
    pub fn insert_hint(&self, hint: VirtAddr, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let align = mapping
            .mapping_size()
            .checked_next_power_of_two()
            .ok_or(SvsmError::Mem)?;
        self.insert_aligned(hint, mapping, align)
    }

    /// Inserts a naturally aligned mapping at the first available address.
    pub fn insert(&self, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        self.insert_hint(SVSM_PERTASK_BASE, mapping)
    }

    /// Removes the mapping starting at `base`.
    pub fn remove(&self, base: VirtAddr) -> Result<Box<VMM>, SvsmError> {
        let mut tree = self.tree.lock_write();
        let node = tree.find_mut(&base.pfn()).remove().ok_or(SvsmError::Mem)?;
        self.unmap_vmm(&node);

        let (start, end) = node.range();
        let region = MemoryRegion::from_addresses(start, end);
        flush_tlb_global_sync_range(region, node.get_mapping().page_size());
        CONTEXT_VMR_ALLOCATOR.free(base);

        Ok(node)
    }

    /// Handles a page fault for an address in this range.
    pub fn handle_page_fault(
        &self,
        pgtbl: &mut PageTable,
        vaddr: VirtAddr,
        write: bool,
    ) -> Result<(), SvsmError> {
        if pgtbl.populate_pgtbl_part(&self.pgtbl_part.lock_read()) {
            return Ok(());
        }

        let tree = self.tree.lock_read();
        let cursor = tree.upper_bound(Bound::Included(&vaddr.pfn()));
        let node = cursor.get().ok_or(SvsmError::Mem)?;
        let (start, end) = node.range();
        if vaddr < start || vaddr >= end {
            return Err(SvsmError::Mem);
        }

        node.get_mapping().handle_page_fault(vaddr - start, write)?;
        Ok(())
    }
}

impl Drop for ContextVMR {
    fn drop(&mut self) {
        let tree = self.tree.get_mut();
        while let Some(node) = tree.front_mut().remove() {
            CONTEXT_VMR_ALLOCATOR.free(node.range().0);
        }
    }
}

/// A mapping in a [`ContextVMR`] that is removed when dropped.
#[derive(Debug)]
pub struct ContextVMRMapping<V: Borrow<ContextVMR>> {
    vmr: V,
    va: VirtAddr,
}

impl<V: Borrow<ContextVMR>> ContextVMRMapping<V> {
    /// Creates a mapping at the first available address.
    pub fn new(vmr: V, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert(mapping)?;
        Ok(Self { vmr, va })
    }

    /// Creates a mapping at an exact address.
    pub fn new_at(vmr: V, addr: VirtAddr, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert_at(addr, mapping)?;
        Ok(Self { vmr, va })
    }

    /// Creates a mapping at or above an address hint.
    pub fn new_hint(vmr: V, addr: VirtAddr, mapping: Mapping) -> Result<Self, SvsmError> {
        let va = vmr.borrow().insert_hint(addr, mapping)?;
        Ok(Self { vmr, va })
    }

    /// Prevents automatic removal and returns the mapping address.
    pub fn leak(self) -> VirtAddr {
        ManuallyDrop::new(self).va
    }

    /// Returns the mapping address.
    pub fn virt_addr(&self) -> VirtAddr {
        self.va
    }
}

impl<V: Borrow<ContextVMR>> Deref for ContextVMRMapping<V> {
    type Target = VirtAddr;

    fn deref(&self) -> &Self::Target {
        &self.va
    }
}

impl<V: Borrow<ContextVMR>> Drop for ContextVMRMapping<V> {
    fn drop(&mut self) {
        self.vmr
            .borrow()
            .remove(self.va)
            .expect("Error removing ContextVMR virtual memory range");
    }
}

#[cfg(test)]
mod tests {
    use super::ContextVMR;
    use crate::error::SvsmError;
    use crate::locking::SpinLock;
    use crate::mm::vm::VMReserved;

    static TEST_LOCK: SpinLock<()> = SpinLock::new(());

    #[test]
    fn allocations_are_unique_between_instances() {
        let _guard = TEST_LOCK.lock();
        let first = ContextVMR::new(Default::default());
        let second = ContextVMR::new(Default::default());
        let first_addr = first.insert(VMReserved::new_mapping(4096)).unwrap();
        let second_addr = second.insert(VMReserved::new_mapping(4096)).unwrap();

        assert_ne!(first_addr, second_addr);

        drop(first);

        let third = ContextVMR::new(Default::default());
        let third_addr = third
            .insert_at(first_addr, VMReserved::new_mapping(4096))
            .unwrap();
        assert_eq!(third_addr, first_addr);
    }

    #[test]
    fn shared_allocations_are_refcounted() {
        let _guard = TEST_LOCK.lock();
        let first = ContextVMR::new(Default::default());
        let second = ContextVMR::new(Default::default());
        let addr = first.alloc_shared(VMReserved::new_mapping(4096)).unwrap();

        assert_eq!(second.map_shared(addr).unwrap(), addr);
        assert!(matches!(second.map_shared(addr), Err(SvsmError::Mem)));

        drop(first);

        let third = ContextVMR::new(Default::default());
        assert!(matches!(
            third.insert_at(addr, VMReserved::new_mapping(4096)),
            Err(SvsmError::Mem)
        ));

        drop(second);

        assert_eq!(
            third
                .insert_at(addr, VMReserved::new_mapping(4096))
                .unwrap(),
            addr
        );
    }

    #[test]
    fn private_allocations_cannot_be_shared() {
        let _guard = TEST_LOCK.lock();
        let first = ContextVMR::new(Default::default());
        let second = ContextVMR::new(Default::default());
        let addr = first.insert(VMReserved::new_mapping(4096)).unwrap();

        assert!(matches!(second.map_shared(addr), Err(SvsmError::Mem)));
    }
}
