// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

use crate::address::Address;
use crate::types::PageSize;
use core::fmt;

/// An abstraction over a memory region, expressed in terms of physical
/// ([`PhysAddr`](crate::address::PhysAddr)) or virtual
/// ([`VirtAddr`](crate::address::VirtAddr)) addresses.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion<A> {
    start: A,
    end: A,
}

impl<A> fmt::Display for MemoryRegion<A>
where
    A: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}-{}]", self.start, self.end)
    }
}

impl<A> fmt::LowerHex for MemoryRegion<A>
where
    A: fmt::LowerHex,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        self.start.fmt(f)?;
        f.write_str("-")?;
        self.end.fmt(f)?;
        f.write_str("]")
    }
}

impl<A> MemoryRegion<A>
where
    A: Address,
{
    /// Create a new memory region starting at address `start`, spanning `len`
    /// bytes.
    pub fn new(start: A, len: usize) -> Self {
        let end = A::from(start.bits() + len);
        Self { start, end }
    }

    /// Create a new memory region with overflow checks.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let start = VirtAddr::from(u64::MAX);
    /// let region = MemoryRegion::checked_new(start, PAGE_SIZE);
    /// assert!(region.is_none());
    /// ```
    pub fn checked_new(start: A, len: usize) -> Option<Self> {
        let end = start.checked_add(len)?;
        Some(Self { start, end })
    }

    /// Create a memory region from two raw addresses.
    pub const fn from_addresses(start: A, end: A) -> Self {
        Self { start, end }
    }

    /// The base address of the memory region, originally set in
    /// [`MemoryRegion::new()`].
    #[inline]
    pub const fn start(&self) -> A {
        self.start
    }

    /// The length of the memory region in bytes, originally set in
    /// [`MemoryRegion::new()`].
    #[inline]
    pub fn len(&self) -> usize {
        self.end.bits().saturating_sub(self.start.bits())
    }

    /// Returns whether the region spans any actual memory.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::utils::MemoryRegion;
    /// let r = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), 0);
    /// assert!(r.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The end address of the memory region.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let base = VirtAddr::from(0xffffff0000u64);
    /// let region = MemoryRegion::new(base, PAGE_SIZE);
    /// assert_eq!(region.end(), VirtAddr::from(0xffffff1000u64));
    /// ```
    #[inline]
    pub const fn end(&self) -> A {
        self.end
    }

    /// Checks whether two regions overlap. This does *not* include contiguous
    /// regions, use [`MemoryRegion::contiguous()`] for that purpose.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let r1 = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// let r2 = MemoryRegion::new(VirtAddr::from(0xffffff2000u64), PAGE_SIZE);
    /// assert!(!r1.overlap(&r2));
    /// ```
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let r1 = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE * 2);
    /// let r2 = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE);
    /// assert!(r1.overlap(&r2));
    /// ```
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// // Contiguous regions do not overlap
    /// let r1 = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// let r2 = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE);
    /// assert!(!r1.overlap(&r2));
    /// ```
    pub fn overlap(&self, other: &Self) -> bool {
        self.start() < other.end() && self.end() > other.start()
    }

    /// Checks whether two regions are contiguous or overlapping. This is a
    /// less strict check than [`MemoryRegion::overlap()`].
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let r1 = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// let r2 = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE);
    /// assert!(r1.contiguous(&r2));
    /// ```
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let r1 = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// let r2 = MemoryRegion::new(VirtAddr::from(0xffffff2000u64), PAGE_SIZE);
    /// assert!(!r1.contiguous(&r2));
    /// ```
    pub fn contiguous(&self, other: &Self) -> bool {
        self.start() <= other.end() && self.end() >= other.start()
    }

    /// Merge two regions. It does not check whether the two regions are
    /// contiguous in the first place, so the resulting region will cover
    /// any non-overlapping memory between both.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let r1 = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// let r2 = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE);
    /// let r3 = r1.merge(&r2);
    /// assert_eq!(r3.start(), r1.start());
    /// assert_eq!(r3.len(), r1.len() + r2.len());
    /// assert_eq!(r3.end(), r2.end());
    /// ```
    pub fn merge(&self, other: &Self) -> Self {
        let start = self.start.min(other.start);
        let end = self.end().max(other.end());
        Self { start, end }
    }

    /// Iterate over the addresses covering the memory region in jumps of the
    /// specified page size. Note that if the base address of the region is not
    /// page aligned, returned addresses will not be aligned either.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::{PAGE_SIZE, PageSize};
    /// # use svsm::utils::MemoryRegion;
    /// let region = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE * 2);
    /// let mut iter = region.iter_pages(PageSize::Regular);
    /// assert_eq!(iter.next(), Some(VirtAddr::from(0xffffff0000u64)));
    /// assert_eq!(iter.next(), Some(VirtAddr::from(0xffffff1000u64)));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn iter_pages(&self, size: PageSize) -> impl Iterator<Item = A> {
        let size = usize::from(size);
        (self.start().bits()..self.end().bits())
            .step_by(size)
            .map(A::from)
    }

    /// Check whether an address is within this region.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::{PAGE_SIZE, PageSize};
    /// # use svsm::utils::MemoryRegion;
    /// let region = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// assert!(region.contains(VirtAddr::from(0xffffff0000u64)));
    /// assert!(region.contains(VirtAddr::from(0xffffff0fffu64)));
    /// assert!(!region.contains(VirtAddr::from(0xffffff1000u64)));
    /// ```
    pub fn contains(&self, addr: A) -> bool {
        self.start() <= addr && addr < self.end()
    }

    /// Check whether an address is within this region, treating `end` as part
    /// of the region.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::{PAGE_SIZE, PageSize};
    /// # use svsm::utils::MemoryRegion;
    /// let region = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE);
    /// assert!(region.contains_inclusive(VirtAddr::from(0xffffff0000u64)));
    /// assert!(region.contains_inclusive(VirtAddr::from(0xffffff0fffu64)));
    /// assert!(region.contains_inclusive(VirtAddr::from(0xffffff1000u64)));
    /// assert!(!region.contains_inclusive(VirtAddr::from(0xffffff1001u64)));
    /// ```
    pub fn contains_inclusive(&self, addr: A) -> bool {
        (self.start()..=self.end()).contains(&addr)
    }

    /// Check whether this region fully contains a different region.
    ///
    /// ```rust
    /// # use svsm::address::VirtAddr;
    /// # use svsm::utils::MemoryRegion;
    /// # use svsm::types::PAGE_SIZE;
    /// let big = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE * 2);
    /// let small = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE);
    /// let overlapping = MemoryRegion::new(VirtAddr::from(0xffffff0000u64), PAGE_SIZE * 2);
    /// assert!(big.contains_region(&small));
    /// assert!(!small.contains_region(&big));
    /// assert!(!overlapping.contains_region(&big));
    /// assert!(!big.contains_region(&overlapping));
    /// ```
    pub fn contains_region(&self, other: &Self) -> bool {
        self.start() <= other.start() && other.end() <= self.end()
    }

    /// Returns a new memory region with the specified added length at the end.
    ///
    /// ```
    /// # use svsm::address::VirtAddr;
    /// # use svsm::types::PAGE_SIZE;
    /// # use svsm::utils::MemoryRegion;
    /// let region = MemoryRegion::new(VirtAddr::from(0xffffff1000u64), PAGE_SIZE);
    /// let bigger = region.expand(PAGE_SIZE);
    /// assert_eq!(bigger.len(), PAGE_SIZE * 2);
    /// ```
    pub fn expand(&self, len: usize) -> Self {
        Self::new(self.start(), self.len() + len)
    }
}
