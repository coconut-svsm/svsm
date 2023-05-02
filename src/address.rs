// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

use crate::types::PAGE_SIZE;
use core::fmt;
use core::ops;

// The backing type to represent an address;
type InnerAddr = usize;

pub trait Address:
    Copy + From<InnerAddr> + Into<InnerAddr> + PartialEq + Eq + PartialOrd + Ord
{
    // Transform the address into its inner representation for easier
    /// arithmetic manipulation
    fn bits(&self) -> InnerAddr {
        (*self).into()
    }

    fn is_null(&self) -> bool {
        self.bits() == 0
    }

    fn align_up(&self, align: InnerAddr) -> Self {
        Self::from((self.bits() + (align - 1)) & !(align - 1))
    }

    fn page_align_up(&self) -> Self {
        self.align_up(PAGE_SIZE)
    }

    fn page_align(&self) -> Self {
        Self::from(self.bits() & !(PAGE_SIZE - 1))
    }

    fn is_aligned(&self, align: InnerAddr) -> bool {
        (self.bits() & (align - 1)) == 0
    }

    fn is_page_aligned(&self) -> bool {
        self.is_aligned(PAGE_SIZE)
    }

    fn offset(&self, off: InnerAddr) -> Self {
        Self::from(self.bits() + off)
    }

    fn checked_offset(&self, off: InnerAddr) -> Option<Self> {
        self.bits().checked_add(off).map(|addr| addr.into())
    }

    fn sub(&self, off: InnerAddr) -> Self {
        Self::from(self.bits() - off)
    }

    fn checked_sub(&self, off: InnerAddr) -> Option<Self> {
        self.bits().checked_sub(off).map(|addr| addr.into())
    }

    fn page_offset(&self) -> usize {
        self.bits() & (PAGE_SIZE - 1)
    }

    fn crosses_page(&self, size: usize) -> bool {
        let start = self.bits();
        let x1 = start / PAGE_SIZE;
        let x2 = (start + size - 1) / PAGE_SIZE;
        x1 != x2
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(InnerAddr);

impl PhysAddr {
    pub const fn null() -> Self {
        Self(0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<InnerAddr> for PhysAddr {
    fn from(addr: InnerAddr) -> PhysAddr {
        Self(addr)
    }
}

impl From<PhysAddr> for InnerAddr {
    fn from(addr: PhysAddr) -> InnerAddr {
        addr.0
    }
}

impl From<u64> for PhysAddr {
    fn from(addr: u64) -> PhysAddr {
        // The unwrap will get optimized away on 64bit platforms,
        // which should be our only target anyway
        let addr: usize = addr.try_into().unwrap();
        PhysAddr::from(addr)
    }
}

impl From<PhysAddr> for u64 {
    fn from(addr: PhysAddr) -> u64 {
        addr.0 as u64
    }
}

// Substracting two addresses produces an usize instead of an address,
// since we normally do this to compute the size of a memory region.
impl ops::Sub for PhysAddr {
    type Output = InnerAddr;
    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}

impl Address for PhysAddr {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(InnerAddr);

impl VirtAddr {
    pub const fn null() -> Self {
        Self(0)
    }

    // const traits experimental, so for now we need this to make up
    // for the lack of VirtAddr::from() in const contexts.
    pub const fn new(addr: InnerAddr) -> Self {
        Self(addr)
    }

    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<InnerAddr> for VirtAddr {
    fn from(addr: InnerAddr) -> Self {
        Self(addr)
    }
}

impl From<VirtAddr> for InnerAddr {
    fn from(addr: VirtAddr) -> Self {
        addr.0
    }
}

impl From<u64> for VirtAddr {
    fn from(addr: u64) -> Self {
        let addr: usize = addr.try_into().unwrap();
        VirtAddr::from(addr)
    }
}

impl From<VirtAddr> for u64 {
    fn from(addr: VirtAddr) -> Self {
        addr.0 as u64
    }
}

impl<T> From<*const T> for VirtAddr {
    fn from(ptr: *const T) -> Self {
        Self(ptr as InnerAddr)
    }
}

impl<T> From<*mut T> for VirtAddr {
    fn from(ptr: *mut T) -> Self {
        Self(ptr as InnerAddr)
    }
}

impl ops::Sub for VirtAddr {
    type Output = InnerAddr;
    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}

impl Address for VirtAddr {}
