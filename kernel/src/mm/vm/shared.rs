// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Advanced Micro Devices, Inc.
// Copyright (c) 2026 SUSE LLC
//
// Author: Joerg Roedel <joerg.roedel@amd.com>
// Author: Carlos López <clopez@suse.de>

//! Allocator for globally unique addresses.

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use crate::mm::vm::{Mapping, VmAllocator, VmRange};
use crate::task::TaskVm;
use crate::utils::unique_va_allocator::UniqueVaAllocator;

use core::cell::Cell;
use core::marker::PhantomData;

/// An allocation within a `GlobalVmAllocator`.
#[derive(Debug)]
struct GlobalVmAllocation {
    shareable: bool,
    refcount: Cell<usize>,
    mapping: Option<Mapping>,
}

impl GlobalVmAllocation {
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

/// A global, shared allocator for globally unique virtual addresses.
#[derive(Debug)]
struct GlobalVmAllocator<V: VmRange> {
    ranges: SpinLock<UniqueVaAllocator<GlobalVmAllocation>>,
    _phantom: PhantomData<V>,
}

impl<V: VmRange> GlobalVmAllocator<V> {
    const fn new() -> Self {
        Self {
            ranges: SpinLock::new(UniqueVaAllocator::new(
                V::DESCRIPTOR.base().as_usize(),
                V::DESCRIPTOR.end().as_usize(),
            )),
            _phantom: PhantomData,
        }
    }

    fn alloc_aligned(&self, hint: VirtAddr, size: usize, align: usize) -> Option<VirtAddr> {
        self.ranges
            .lock()
            .alloc_aligned_hint(hint.as_usize(), size, align, GlobalVmAllocation::private())
            .map(VirtAddr::from)
    }

    fn alloc_at(&self, addr: VirtAddr, size: usize) -> Option<VirtAddr> {
        self.ranges
            .lock()
            .alloc_at(addr.as_usize(), size, GlobalVmAllocation::private())
            .map(VirtAddr::from)
    }

    fn alloc_shared(&self, mapping: Mapping) -> Option<VirtAddr> {
        let size = mapping.mapping_size();
        let allocation = GlobalVmAllocation::shared(mapping);

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
                .expect("global allocation refcount underflow");
            allocation.refcount.set(refcount);
            if refcount != 0 {
                return;
            }
        }

        ranges.free(addr.as_usize());
    }
}

/// A virtual address allocator for globally-unique addresses.
///
/// Reservations are globally unique across all contexts, handed out by the
/// shared [`GlobalVmAllocator`], while each instance keeps its own record of
/// the mappings installed in it.
#[derive(Debug)]
struct SharedVmAllocator<V: VmRange + 'static> {
    shared: &'static GlobalVmAllocator<V>,
    local: RWLock<UniqueVaAllocator<Mapping>>,
}

impl<V: VmRange + 'static> SharedVmAllocator<V> {
    fn new(shared: &'static GlobalVmAllocator<V>) -> Self {
        Self {
            shared,
            local: RWLock::new(UniqueVaAllocator::new(
                V::DESCRIPTOR.base().as_usize(),
                V::DESCRIPTOR.end().as_usize(),
            )),
        }
    }

    fn insert_local(&self, base: VirtAddr, size: usize, mapping: Mapping) -> Result<(), SvsmError> {
        self.local
            .lock_write()
            .alloc_at(base.as_usize(), size, mapping)
            .map(|_| ())
            .ok_or(SvsmError::Mem)
    }

    /// Reserves a globally unique, shareable mapping and records it locally.
    pub fn alloc_shared(&self, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let size = mapping.mapping_size();
        let base = self
            .shared
            .alloc_shared(mapping.clone())
            .ok_or(SvsmError::Mem)?;
        if let Err(error) = self.insert_local(base, size, mapping) {
            self.shared.free(base);
            return Err(error);
        }
        Ok(base)
    }

    /// Maps an existing shared allocation into this instance, returning its
    /// mapping.
    pub fn map_shared(&self, addr: VirtAddr) -> Result<Mapping, SvsmError> {
        let mapping = self.shared.map_shared(addr).ok_or(SvsmError::Mem)?;
        let size = mapping.mapping_size();
        if let Err(error) = self.insert_local(addr, size, mapping.clone()) {
            self.shared.free(addr);
            return Err(error);
        }
        Ok(mapping)
    }

    fn alloc(
        &self,
        hint: VirtAddr,
        size: usize,
        align: usize,
        mapping: Mapping,
    ) -> Result<VirtAddr, SvsmError> {
        let base = self
            .shared
            .alloc_aligned(hint, size, align)
            .ok_or(SvsmError::Mem)?;
        if let Err(error) = self.insert_local(base, size, mapping) {
            self.shared.free(base);
            return Err(error);
        }
        Ok(base)
    }

    fn alloc_at(&self, at: VirtAddr, size: usize, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        let base = self.shared.alloc_at(at, size).ok_or(SvsmError::Mem)?;
        if let Err(error) = self.insert_local(base, size, mapping) {
            self.shared.free(base);
            return Err(error);
        }
        Ok(base)
    }

    fn free<F>(&self, base: VirtAddr, teardown: F) -> Option<Mapping>
    where
        F: FnOnce(&Mapping),
    {
        // Claim the mapping from the local tree first. This ensures,
        // for concurrent users of this allocator:
        // * The same allocation cannot be doubly freed
        // * The same allocation can be reserved locally, but the operation
        //   will block until this transaction has been committed globally
        //   below.
        let mapping = self.local.lock_write().remove(base.as_usize())?;

        // Tear down the mapping while it is still reserved globally, preventing
        // it from being handed out by the allocator. Local lock has been dropped.
        teardown(&mapping);

        // Commit the transaction globally.
        self.shared.free(base);
        Some(mapping)
    }

    fn query(&self, addr: VirtAddr) -> Option<(VirtAddr, Mapping)> {
        self.local
            .lock_read()
            .get_containing(addr.as_usize())
            .map(|(base, mapping)| (VirtAddr::from(base), mapping.clone()))
    }

    fn for_each<F: FnMut(VirtAddr, &Mapping)>(&self, mut f: F) {
        for (start, _, mapping) in self.local.lock_read().iter() {
            f(VirtAddr::from(start), mapping);
        }
    }
}

impl<V: VmRange + 'static> Drop for SharedVmAllocator<V> {
    fn drop(&mut self) {
        // Release every reservation this instance still holds from the shared
        // pool. The local allocator's own nodes are freed when it is dropped.
        let local = self.local.get_mut();
        for (start, _, _) in local.iter() {
            self.shared.free(VirtAddr::from(start));
        }
    }
}

#[derive(Debug)]
pub struct TaskVmAllocator {
    inner: SharedVmAllocator<TaskVm>,
}

impl TaskVmAllocator {
    pub fn alloc_shared(&self, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        self.inner.alloc_shared(mapping)
    }

    pub fn map_shared(&self, addr: VirtAddr) -> Result<Mapping, SvsmError> {
        self.inner.map_shared(addr)
    }
}

impl VmAllocator<TaskVm> for TaskVmAllocator {
    fn new() -> Self {
        /// Static singleton to ensure global address uniqueness
        static TASK_VM_ALLOCATOR: GlobalVmAllocator<TaskVm> = GlobalVmAllocator::new();

        Self {
            inner: SharedVmAllocator::new(&TASK_VM_ALLOCATOR),
        }
    }

    fn alloc(
        &self,
        hint: VirtAddr,
        size: usize,
        align: usize,
        mapping: Mapping,
    ) -> Result<VirtAddr, SvsmError> {
        self.inner.alloc(hint, size, align, mapping)
    }

    fn alloc_at(&self, at: VirtAddr, size: usize, mapping: Mapping) -> Result<VirtAddr, SvsmError> {
        self.inner.alloc_at(at, size, mapping)
    }

    fn free<F: FnOnce(&Mapping)>(&self, base: VirtAddr, teardown: F) -> Option<Mapping> {
        self.inner.free(base, teardown)
    }

    fn query(&self, addr: VirtAddr) -> Option<(VirtAddr, Mapping)> {
        self.inner.query(addr)
    }

    fn for_each<F: FnMut(VirtAddr, &Mapping)>(&self, f: F) {
        self.inner.for_each(f);
    }
}
