// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

use crate::mm::virt_to_phys;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};

use core::fmt;
use core::ops;
use core::slice;

use builtin_macros::*;

#[cfg(verus_keep_ghost)]
include!("address.verus.rs");

// The backing type to represent an address;
type InnerAddr = usize;

#[verus_verify]
const SIGN_BIT: usize = 47;

#[inline]
#[verus_verify]
#[ensures(|ret: InnerAddr| sign_extend_ensures(addr, ret))]
const fn sign_extend(addr: InnerAddr) -> InnerAddr {
    let mask = 1usize << SIGN_BIT;
    if (addr & mask) == mask {
        addr | !((1usize << SIGN_BIT) - 1)
    } else {
        addr & ((1usize << SIGN_BIT) - 1)
    }
}

#[verus_verify]
pub trait Address:
    Copy + From<InnerAddr> + Into<InnerAddr> + PartialEq + Eq + PartialOrd + Ord
{
    // Transform the address into its inner representation for easier
    /// arithmetic manipulation
    #[inline]
    #[verus_verify]
    #[ensures(|ret: InnerAddr| ret === from_spec(*self))]
    fn bits(&self) -> InnerAddr {
        (*self).into()
    }

    #[inline]
    #[verus_verify]
    #[ensures(|ret: bool| ret == (from_spec(*self) === 0usize))]
    fn is_null(&self) -> bool {
        self.bits() == 0
    }

    #[inline]
    #[verus_verify]
    #[requires(align_up_requires(from_spec(*self), align))]
    #[ensures(|ret: Self| ret === addr_align_up(*self, align))]
    fn align_up(&self, align: InnerAddr) -> Self {
        Self::from((self.bits() + (align - 1)) & !(align - 1))
    }

    #[inline]
    #[verus_verify]
    #[requires(align_up_requires(from_spec(*self), PAGE_SIZE))]
    #[ensures(|ret: Self| ret === addr_page_align_up(*self))]
    fn page_align_up(&self) -> Self {
        self.align_up(PAGE_SIZE)
    }

    #[inline]
    #[verus_verify]
    #[requires(align_requires(PAGE_SIZE))]
    #[ensures(|ret: Self| ret === addr_page_align_down(*self))]
    fn page_align(&self) -> Self {
        Self::from(self.bits() & !(PAGE_SIZE - 1))
    }

    #[inline]
    #[verus_verify]
    #[requires(align_requires(align))]
    #[ensures(|ret: bool| ret == addr_is_aligned_spec(*self, align))]
    fn is_aligned(&self, align: InnerAddr) -> bool {
        (self.bits() & (align - 1)) == 0
    }

    #[inline]
    #[verus_verify(external_body)]
    #[requires(align_requires(core::mem::align_of::<T>()))]
    #[ensures(|ret: bool| ret == addr_is_aligned_spec(*self, core::mem::align_of::<T>()))]
    fn is_aligned_to<T>(&self) -> bool {
        self.is_aligned(core::mem::align_of::<T>())
    }

    #[inline]
    #[verus_verify]
    #[ensures(|ret: bool| ret == addr_is_page_aligned_spec(*self))]
    fn is_page_aligned(&self) -> bool {
        self.is_aligned(PAGE_SIZE)
    }

    #[inline]
    #[verus_verify]
    fn checked_add(&self, off: InnerAddr) -> Option<Self> {
        self.bits().checked_add(off).map(|addr| addr.into())
    }

    #[inline]
    #[verus_verify]
    fn checked_sub(&self, off: InnerAddr) -> Option<Self> {
        self.bits().checked_sub(off).map(|addr| addr.into())
    }

    #[inline]
    #[verus_verify]
    fn saturating_add(&self, off: InnerAddr) -> Self {
        Self::from(self.bits().saturating_add(off))
    }

    #[inline]
    #[verus_verify]
    fn page_offset(&self) -> usize {
        self.bits() & (PAGE_SIZE - 1)
    }

    #[inline]
    #[verus_verify]
    #[requires(
        size > 0,
        from_spec::<_, InnerAddr>(*self) + size <= InnerAddr::MAX
    )]
    #[ensures(|ret: bool | ret == crosses_page_spec(*self, size))]
    fn crosses_page(&self, size: usize) -> bool {
        let start = self.bits();
        let x1 = start / PAGE_SIZE;
        let x2 = (start + size - 1) / PAGE_SIZE;
        x1 != x2
    }

    #[inline]
    #[verus_verify]
    #[ensures(|ret: InnerAddr| ret == pfn_spec(from_spec(*self)))]
    fn pfn(&self) -> InnerAddr {
        self.bits() >> PAGE_SHIFT
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(InnerAddr);

impl PhysAddr {
    #[inline]
    pub const fn new(p: InnerAddr) -> Self {
        Self(p)
    }

    #[inline]
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
    #[inline]
    fn from(addr: InnerAddr) -> PhysAddr {
        Self(addr)
    }
}

impl From<PhysAddr> for InnerAddr {
    #[inline]
    fn from(addr: PhysAddr) -> InnerAddr {
        addr.0
    }
}

impl From<u64> for PhysAddr {
    #[inline]
    fn from(addr: u64) -> PhysAddr {
        // The unwrap will get optimized away on 64bit platforms,
        // which should be our only target anyway
        let addr: usize = addr.try_into().unwrap();
        PhysAddr::from(addr)
    }
}

impl From<PhysAddr> for u64 {
    #[inline]
    fn from(addr: PhysAddr) -> u64 {
        addr.0 as u64
    }
}

// Substracting two addresses produces an usize instead of an address,
// since we normally do this to compute the size of a memory region.
impl ops::Sub<PhysAddr> for PhysAddr {
    type Output = InnerAddr;

    #[inline]
    fn sub(self, other: PhysAddr) -> Self::Output {
        self.0 - other.0
    }
}

// Adding and subtracting usize to PhysAddr gives a new PhysAddr
impl ops::Sub<InnerAddr> for PhysAddr {
    type Output = Self;

    #[inline]
    fn sub(self, other: InnerAddr) -> Self {
        PhysAddr::from(self.0 - other)
    }
}

impl ops::Add<InnerAddr> for PhysAddr {
    type Output = Self;

    #[inline]
    fn add(self, other: InnerAddr) -> Self {
        PhysAddr::from(self.0 + other)
    }
}

impl Address for PhysAddr {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[verus_verify]
pub struct VirtAddr(InnerAddr);

#[verus_verify]
impl VirtAddr {
    #[inline]
    #[verus_verify]
    pub const fn null() -> Self {
        Self(0)
    }

    // const traits experimental, so for now we need this to make up
    // for the lack of VirtAddr::from() in const contexts.
    #[inline]
    #[verus_verify]
    #[ensures(|ret: VirtAddr| ret.new_ensures(addr))]
    pub const fn new(addr: InnerAddr) -> Self {
        Self(sign_extend(addr))
    }

    /// Returns the index into page-table pages of given levels.
    #[verus_verify]
    #[requires(L <= 5)]
    #[ensures(|ret: usize| self.pgtbl_idx_ensures(L, ret))]
    pub const fn to_pgtbl_idx<const L: usize>(&self) -> usize {
        (self.0 >> (12 + L * 9)) & 0x1ffusize
    }

    #[inline]
    #[verus_verify(external_body)]
    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    #[verus_verify(external_body)]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub const fn as_usize(&self) -> usize {
        self.0
    }

    /// Converts the `VirtAddr` to a reference to the given type, checking
    /// that the address is not NULL and properly aligned.
    ///
    /// # Safety
    ///
    /// All safety requirements for pointers apply, minus alignment and NULL
    /// checks, which this function already does.
    #[inline]
    #[verus_verify(external_body)]
    pub unsafe fn aligned_ref<'a, T>(&self) -> Option<&'a T> {
        self.is_aligned_to::<T>()
            .then(|| unsafe { self.as_ptr::<T>().as_ref() })
            .flatten()
    }

    /// Converts the `VirtAddr` to a reference to the given type, checking
    /// that the address is not NULL and properly aligned.
    ///
    /// # Safety
    ///
    /// All safety requirements for pointers apply, minus alignment and NULL
    /// checks, which this function already does.
    #[inline]
    #[verus_verify(external)]
    pub unsafe fn aligned_mut<'a, T>(&self) -> Option<&'a mut T> {
        self.is_aligned_to::<T>()
            .then(|| unsafe { self.as_mut_ptr::<T>().as_mut() })
            .flatten()
    }

    #[verus_verify]
    #[requires(self.const_add_requires(offset))]
    #[ensures(|ret: VirtAddr| self.const_add_ensures(offset, ret))]
    pub const fn const_add(&self, offset: usize) -> Self {
        proof! {use_type_invariant(self);}
        VirtAddr::new(self.0 + offset)
    }

    pub const fn const_sub(&self, offset: usize) -> Self {
        VirtAddr::new(self.0 - offset)
    }

    /// Converts the `VirtAddr` to a slice of a given type
    ///
    /// # Arguments:
    ///
    /// * `len` - Number of elements of type `T` in the slice
    ///
    /// # Returns
    ///
    /// Slice with `len` elements of type `T`
    ///
    /// # Safety
    ///
    /// All Safety requirements from [`core::slice::from_raw_parts`] for the
    /// data pointed to by the `VirtAddr` apply here as well.
    #[verus_verify(external_body)]
    pub unsafe fn to_slice<T>(&self, len: usize) -> &[T] {
        unsafe { slice::from_raw_parts::<T>(self.as_ptr::<T>(), len) }
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

#[verus_verify]
impl From<InnerAddr> for VirtAddr {
    #[inline]
    #[verus_verify]
    #[ensures(|ret: VirtAddr| ret.new_ensures(addr))]
    fn from(addr: InnerAddr) -> Self {
        Self(sign_extend(addr))
    }
}

#[verus_verify]
impl From<VirtAddr> for InnerAddr {
    #[inline]
    #[verus_verify]
    #[ensures(|ret: InnerAddr| addr@ == ret)]
    fn from(addr: VirtAddr) -> Self {
        addr.0
    }
}

impl From<u64> for VirtAddr {
    #[inline]
    #[verus_verify(external_body)]
    #[ensures(|ret: Self| ret.new_ensures(addr as usize))]
    fn from(addr: u64) -> Self {
        let addr: usize = addr.try_into().unwrap();
        VirtAddr::from(addr)
    }
}

#[verus_verify]
impl From<VirtAddr> for u64 {
    #[inline]
    #[verus_verify]
    #[ensures(|ret: Self| ret == addr@)]
    fn from(addr: VirtAddr) -> Self {
        addr.0 as u64
    }
}

#[verus_verify]
impl<T> From<*const T> for VirtAddr {
    #[inline]
    #[verus_verify]
    fn from(ptr: *const T) -> Self {
        Self::from(ptr as InnerAddr)
    }
}

#[verus_verify]
impl<T> From<*mut T> for VirtAddr {
    #[verus_verify]
    fn from(ptr: *mut T) -> Self {
        Self::from(ptr as InnerAddr)
    }
}

#[verus_verify]
impl ops::Sub<VirtAddr> for VirtAddr {
    type Output = InnerAddr;

    #[inline]
    #[verus_verify]
    #[requires(self.sub_requires(other))]
    #[ensures(|ret: InnerAddr| self.sub_ensures(other, ret))]
    fn sub(self, other: VirtAddr) -> Self::Output {
        sign_extend(self.0 - other.0)
    }
}

#[verus_verify]
impl ops::Sub<usize> for VirtAddr {
    type Output = Self;

    #[inline]
    #[verus_verify]
    #[requires(self.sub_usize_requires(other))]
    #[ensures(|ret: Self| self.sub_usize_ensures(other, ret))]
    fn sub(self, other: usize) -> Self {
        VirtAddr::from(self.0 - other)
    }
}

#[verus_verify]
impl ops::Add<InnerAddr> for VirtAddr {
    type Output = VirtAddr;

    #[verus_verify]
    #[requires(self.const_add_requires(other))]
    #[ensures(|ret: VirtAddr| self.const_add_ensures(other, ret))]
    fn add(self, other: InnerAddr) -> Self {
        proof! {use_type_invariant(self);}
        VirtAddr::from(self.0 + other)
    }
}

#[verus_verify]
impl Address for VirtAddr {
    #[inline]
    #[verus_verify]
    fn checked_add(&self, off: InnerAddr) -> Option<Self> {
        self.bits()
            .checked_add(off)
            .map(|addr| sign_extend(addr).into())
    }

    #[inline]
    #[verus_verify]
    fn checked_sub(&self, off: InnerAddr) -> Option<Self> {
        self.bits()
            .checked_sub(off)
            .map(|addr| sign_extend(addr).into())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VirtPhysPair {
    pub vaddr: VirtAddr,
    pub paddr: PhysAddr,
}

impl VirtPhysPair {
    pub fn new(vaddr: VirtAddr) -> Self {
        Self {
            vaddr,
            paddr: virt_to_phys(vaddr),
        }
    }
}
