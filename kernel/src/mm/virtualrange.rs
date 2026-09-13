// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023, 2026 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>
// Author: Carlos López <clopez@suse.de>

use crate::address::VirtAddr;
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;
use crate::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator1024};
use core::fmt::Debug;
use core::marker::PhantomData;

use super::{AddrSpaceDescriptor, PERCPU_TEMP_2M, PERCPU_TEMP_4K};

pub const VIRT_ALIGN_4K: usize = PAGE_SHIFT - 12;
pub const VIRT_ALIGN_2M: usize = PAGE_SHIFT_2M - 12;

/// A trait describing an allocatable virtual address range.
pub trait SubVmRange: Sized {
    /// The address space portion that corresponds to this virtual range.
    const DESCRIPTOR: AddrSpaceDescriptor;

    /// The size of virtual address allocations within this virtual range.
    const GRANULE: usize;

    /// Whether to add guard slots between allocations or not.
    const GUARD_SLOTS: bool = true;

    /// Get the allocator for this virtual range.
    fn get_allocator() -> impl core::ops::DerefMut<Target = SubVmAllocator<Self>>;
}

/// A virtual address allocator for a particular address range `A`.
#[derive(Debug, Default)]
pub struct SubVmAllocator<A: SubVmRange> {
    bits: BitmapAllocator1024,
    _phantom: PhantomData<A>,
}

impl<A: SubVmRange> SubVmAllocator<A> {
    pub const CAPACITY: usize = BitmapAllocator1024::CAPACITY;

    pub const fn new() -> Self {
        const { assert!(A::DESCRIPTOR.size() / A::GRANULE <= Self::CAPACITY) }
        Self {
            bits: BitmapAllocator1024::new_full(),
            _phantom: PhantomData,
        }
    }

    pub fn init(&mut self) {
        let count = A::DESCRIPTOR.size() / A::GRANULE;
        self.bits.set(0, count, false);
    }

    pub fn alloc(&mut self, mut count: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
        // Always reserve an extra page to leave a guard between virtual memory allocations
        if A::GUARD_SLOTS {
            count += 1;
        }
        match self.bits.alloc(count, alignment) {
            Some(offset) => Ok(A::DESCRIPTOR.base() + (offset * A::GRANULE)),
            None => Err(SvsmError::Mem),
        }
    }

    pub fn free(&mut self, vaddr: VirtAddr, mut count: usize) {
        let offset = (vaddr - A::DESCRIPTOR.base()) / A::GRANULE;
        // Add 1 to the page count for the VM guard
        if A::GUARD_SLOTS {
            count += 1;
        }
        self.bits.free(offset, count);
    }

    pub fn used_pages(&self) -> usize {
        self.bits.used()
    }

    pub const fn descriptor(&self) -> AddrSpaceDescriptor {
        A::DESCRIPTOR
    }
}

pub fn virt_log_usage() {
    let unused_cap_4k = BitmapAllocator1024::CAPACITY - PERCPU_TEMP_4K.size() / PAGE_SIZE;
    let unused_cap_2m = BitmapAllocator1024::CAPACITY - PERCPU_TEMP_2M.size() / PAGE_SIZE_2M;

    log::info!(
        "[CPU {}] Virtual memory pages used: {} * 4K, {} * 2M",
        this_cpu().get_cpu_index(),
        this_cpu().vrange_4k().used_pages() - unused_cap_4k,
        this_cpu().vrange_2m().used_pages() - unused_cap_2m
    );
}

/// An allocation within a sub-range of the virtual address space.
#[derive(Debug)]
pub struct SubVmAlloc<A: SubVmRange> {
    region: MemoryRegion<VirtAddr>,
    _phantom: PhantomData<A>,
}

impl<A: SubVmRange> SubVmAlloc<A> {
    /// Returns a virtual memory region in the given virtual range.
    pub fn new(count: usize, align: usize) -> Result<Self, SvsmError> {
        let addr = A::get_allocator().alloc(count, align)?;
        let region = MemoryRegion::new(addr, count * A::GRANULE);
        Ok(Self {
            region,
            _phantom: PhantomData,
        })
    }

    /// Returns the virtual memory region that this allocation spans.
    pub const fn region(&self) -> MemoryRegion<VirtAddr> {
        self.region
    }
}

impl<A: SubVmRange> Drop for SubVmAlloc<A> {
    fn drop(&mut self) {
        let region = self.region();
        A::get_allocator().free(region.start(), region.len() / A::GRANULE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::VirtAddr;
    use crate::locking::{LockGuard, SpinLock};
    use crate::mm::AddrSpaceDescriptor;
    use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};

    static TEST_VRANGE_4K: SpinLock<SubVmAllocator<TestRange4k>> =
        SpinLock::new(SubVmAllocator::new());
    static TEST_VRANGE_2M: SpinLock<SubVmAllocator<TestRange2m>> =
        SpinLock::new(SubVmAllocator::new());

    struct TestRange4k {}

    impl SubVmRange for TestRange4k {
        const DESCRIPTOR: AddrSpaceDescriptor =
            AddrSpaceDescriptor::new(VirtAddr::new(0x1000000), 1024 * PAGE_SIZE);
        const GRANULE: usize = PAGE_SIZE;

        fn get_allocator() -> impl core::ops::DerefMut<Target = SubVmAllocator<Self>> {
            TEST_VRANGE_4K.try_lock().unwrap()
        }
    }

    struct TestRange2m {}

    impl SubVmRange for TestRange2m {
        const DESCRIPTOR: AddrSpaceDescriptor =
            AddrSpaceDescriptor::new(VirtAddr::new(0x1000000), 1024 * PAGE_SIZE_2M);
        const GRANULE: usize = PAGE_SIZE_2M;

        fn get_allocator() -> impl core::ops::DerefMut<Target = SubVmAllocator<Self>> {
            TEST_VRANGE_2M.try_lock().unwrap()
        }
    }

    fn range_4k() -> LockGuard<'static, SubVmAllocator<TestRange4k>> {
        let mut guard = TEST_VRANGE_4K.lock();
        guard.init();
        guard
    }

    fn range_2m() -> LockGuard<'static, SubVmAllocator<TestRange2m>> {
        let mut guard = TEST_VRANGE_2M.lock();
        guard.init();
        guard
    }

    #[test]
    fn test_alloc_no_overlap_4k() {
        let mut range = range_4k();

        // Test that we get two virtual addresses that do
        // not overlap when using 4k pages.
        let v1 = range.alloc(12, 0);
        let v2 = range.alloc(12, 0);
        let v1 = u64::from(v1.unwrap());
        let v2 = u64::from(v2.unwrap());

        assert!(v1 < v2);
        assert!((v1 + (12 * PAGE_SIZE as u64)) < v2);
    }

    #[test]
    fn test_alloc_no_overlap_2m() {
        let mut range = range_2m();

        // Test that we get two virtual addresses that do
        // not overlap when using 2M pages.
        let v1 = range.alloc(12, 0);
        let v2 = range.alloc(12, 0);
        let v1 = u64::from(v1.unwrap());
        let v2 = u64::from(v2.unwrap());

        assert!(v1 < v2);
        assert!((v1 + (12 * PAGE_SIZE_2M as u64)) < v2);
    }

    #[test]
    fn test_free_4k() {
        let mut range = range_4k();

        // This checks that freeing an allocated range giving the size
        // of the virtual region in bytes does indeed free the correct amount
        // of pages for 4K ranges.
        let v1 = range.alloc(26, 0).unwrap();
        // Page count will be 1 higher due to guard page.
        assert_eq!(range.used_pages(), 27);

        // If the page size calculation is wrong then there will be a mismatch between
        // the requested and freed page count.
        range.free(v1, 12);
        assert_eq!(range.used_pages(), 14);
        range.free(VirtAddr::new(u64::from(v1) as usize + (13 * PAGE_SIZE)), 13);
        assert_eq!(range.used_pages(), 0);
    }

    #[test]
    fn test_free_2m() {
        let mut range = range_2m();

        // This checks that freeing an allocated range giving the size
        // of the virtual region in bytes does indeed free the correct amount
        // of pages for 4K ranges.
        let v1 = range.alloc(26, 0).unwrap();
        // Page count will be 1 higher due to guard page.
        assert_eq!(range.used_pages(), 27);

        // If the page size calculation is wrong then there will be a mismatch between
        // the requested and freed page count.
        range.free(v1, 12);
        assert_eq!(range.used_pages(), 14);
        range.free(
            VirtAddr::new(u64::from(v1) as usize + (13 * PAGE_SIZE_2M)),
            13,
        );
        assert_eq!(range.used_pages(), 0);
    }
}
