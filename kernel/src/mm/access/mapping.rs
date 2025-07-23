// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

extern crate alloc;

use super::super::{virtualrange::VRangeAlloc, PAGE_SIZE_2M};
use super::{
    Mapping, MappingRead, MappingWrite, ReadableMapping, ReadableSliceMapping, WriteableMapping,
    WriteableSliceMapping,
};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::{flush_address_percpu, percpu::this_cpu};
use crate::error::SvsmError;
use crate::mm::pagetable::PTEntryFlags;
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use zerocopy::{FromBytes, IntoBytes};

/// A guard structure that allows access to mapped data, and which
/// unmaps the backing memory on drop.
#[derive(Debug)]
pub struct OwnedMapping<A, T: ?Sized> {
    mem: VRangeAlloc,
    // Offset within the mapping where `T` resides
    off: usize,
    // Dynamic size for slices, otherwise unused
    len: usize,
    _phantom1: PhantomData<T>,
    _phantom2: PhantomData<A>,
}

impl<A, T: ?Sized> OwnedMapping<A, T> {
    /// Returns the virtual memory region of the whole mapping. Note
    /// that this might not correspond to the region where `T` resides
    /// if the address provided to the constructor was not page aligned.
    ///
    /// If you want the region where `T` resides, see
    /// [`Self::data_vregion()`].
    #[inline]
    pub fn mapping_vregion(&self) -> MemoryRegion<VirtAddr> {
        self.mem.region()
    }

    #[inline]
    pub(super) fn as_ptr<U>(&self) -> *const U {
        (self.mem.region().start() + self.off).as_ptr()
    }

    #[inline]
    pub(super) fn as_mut_ptr<U>(&self) -> *mut U {
        (self.mem.region().start() + self.off).as_mut_ptr()
    }

    /// See the documentation for [`Mapping::borrow_at()`]
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        let start = self
            .mem
            .region()
            .start()
            .checked_add(self.off)
            .and_then(|a| a.checked_add(byte_off))
            .ok_or(SvsmError::ArithOverflow)?;
        if !start.is_aligned_to::<U>() {
            return Err(SvsmError::MemAlign);
        }
        let end = start
            .checked_add(size_of::<U>())
            .filter(|end| *end <= self.mem.region().end())
            .ok_or(SvsmError::MemOverflow)?;
        let region = MemoryRegion::from_addresses(start, end);

        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }

    /// See the documentation for [`Mapping::borrow_slice_at()`]
    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        let start = self
            .mem
            .region()
            .start()
            .checked_add(self.off)
            .and_then(|a| a.checked_add(byte_off))
            .ok_or(SvsmError::ArithOverflow)?;
        if !start.is_aligned_to::<U>() {
            return Err(SvsmError::MemAlign);
        }
        let slice_len = len.checked_mul(size_of::<U>()).ok_or(SvsmError::Mem)?;
        let end = start
            .checked_add(slice_len)
            .filter(|end| *end <= self.mem.region().end())
            .ok_or(SvsmError::MemOverflow)?;
        let region = MemoryRegion::from_addresses(start, end);

        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }
}

impl<A, T> OwnedMapping<A, T> {
    /// Returns the equivalent [`BorrowedMapping`]. This is used to implement
    /// trait methods reusing [`BorrowedMapping`] functionality.
    #[inline]
    pub(super) fn as_borrow(&self) -> BorrowedMapping<'_, A, T> {
        BorrowedMapping {
            region: self.data_vregion(),
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        }
    }

    /// Returns the virtual memory region where `T` resides. Note that this area
    /// might not correspond to the size of the whole mapping if `T` starts at
    /// some non-zero offset or if `T` is smaller than the page size.
    ///
    /// If you want the region for the whole mapping, see
    /// [`Self::mapping_vregion()`].
    pub fn data_vregion(&self) -> MemoryRegion<VirtAddr> {
        // TODO: enable this for [T] as well
        let start = self.mem.region().start().const_add(self.off);
        let end = start.const_add(size_of::<T>());
        MemoryRegion::from_addresses(start, end)
    }

    /// Returns the physical memory region to be mapped for the given physical
    /// address and total count of instancess of `T`.
    ///
    /// Note that this function considers the case where the given address is
    /// not aligned to a page. In that case, the beginning of the region is
    /// aligned down to the page size. The end of the region is always aligned
    /// up to the end of the last page.
    pub(super) fn phys_region(
        paddr: PhysAddr,
        len: usize,
    ) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        let byte_len = len
            .checked_mul(size_of::<T>())
            .ok_or(SvsmError::ArithOverflow)?;
        let end = paddr
            .checked_add(byte_len)
            .ok_or(SvsmError::ArithOverflow)?
            .page_align_up();
        Ok(MemoryRegion::from_addresses(paddr.page_align(), end))
    }

    /// Maps the physical region for the given address and count of instances of
    /// `T` (see [`Self::phys_region()`]). It also checks that the given address
    /// is properly aligned to hold a `T`.
    ///
    /// This function attempts to map the region with a huge mapping whenever
    /// physical alignment allows for it.
    fn map_common<const SHARED: bool>(
        paddr: PhysAddr,
        len: usize,
    ) -> Result<VRangeAlloc, SvsmError> {
        if !paddr.is_aligned_to::<T>() {
            return Err(SvsmError::MemAlign);
        }

        let pregion = Self::phys_region(paddr, len)?;

        let flags = PTEntryFlags::data();
        let huge =
            pregion.start().is_aligned(PAGE_SIZE_2M) && pregion.end().is_aligned(PAGE_SIZE_2M);

        if huge {
            let mem = VRangeAlloc::new_2m(pregion.len(), 0)?;
            this_cpu()
                .get_pgtable()
                .map_region_2m(mem.region(), pregion.start(), flags, SHARED)?;
            Ok(mem)
        } else {
            let mem = VRangeAlloc::new_4k(pregion.len(), 0)?;
            this_cpu()
                .get_pgtable()
                .map_region_4k(mem.region(), pregion.start(), flags, SHARED)?;
            Ok(mem)
        }
    }

    /// Maps the given physical address as an instance of `T`.
    pub(super) fn map<const SHARED: bool>(paddr: PhysAddr) -> Result<Self, SvsmError> {
        let off = paddr.page_offset();
        let mem = Self::map_common::<SHARED>(paddr, 1)?;
        Ok(OwnedMapping {
            mem,
            off,
            len: 1,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }

    /// Maps the given physical address as collection of `len` instances of `T`.
    pub(super) fn map_slice<const SHARED: bool>(
        paddr: PhysAddr,
        len: usize,
    ) -> Result<OwnedMapping<A, [T]>, SvsmError> {
        let off = paddr.page_offset();
        let mem = Self::map_common::<SHARED>(paddr, len)?;
        Ok(OwnedMapping {
            mem,
            off,
            len,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }
}

impl<A, T> OwnedMapping<A, [T]> {
    /// Returns the length of the backing slice
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the backing slice is empty
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the equivalent [`BorrowedMapping`]. This is used to implement
    /// trait methods reusing [`BorrowedMapping`] functionality.
    #[inline]
    pub(super) fn as_borrowed_slice(&self) -> BorrowedMapping<'_, A, [T]> {
        let start = self.mem.region().start().const_add(self.off);
        let end = start.const_add(self.len * size_of::<T>());
        BorrowedMapping {
            region: MemoryRegion::from_addresses(start, end),
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        }
    }
}

impl<A: MappingWrite> OwnedMapping<A, [u8]> {
    /// Fill the backing slice with the given byte.
    pub fn fill(&mut self, val: u8) -> Result<(), SvsmError> {
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe { A::write_bytes(self.as_mut_ptr::<u8>(), self.len, val) }?;
        Ok(())
    }
}

impl<A, T: ?Sized> Drop for OwnedMapping<A, T> {
    fn drop(&mut self) {
        let region = self.mem.region();
        let size = if self.mem.huge() {
            this_cpu().get_pgtable().unmap_region_2m(region);
            PageSize::Huge
        } else {
            this_cpu().get_pgtable().unmap_region_4k(region);
            PageSize::Regular
        };
        // This iterative flush is acceptable for same-CPU mappings because no
        // broadcast is involved for each iteration.
        for page in region.iter_pages(size) {
            flush_address_percpu(page);
        }
    }
}

/// A structure that allows access to mapped memory, but which does not own the
/// mapping, and thus will not unmap memory on drop.
///
/// The lifetime `'a` corresponds to the lifetime of the original mapping. If
/// for example this structure is created from [`OwnedMapping::borrow()`], this
/// structure's lifetime is limited to that of the original owned mapping.
///
/// Note that further borrowing from this type can only result in a smaller
/// (i.e. more restrictive) borrow. This type only has the notion of a region
/// with the size of `T` and will never give out a borrow outside its bounds.
#[derive(Debug, Clone, Copy)]
pub struct BorrowedMapping<'a, A, T: ?Sized> {
    pub(super) region: MemoryRegion<VirtAddr>,
    pub(super) _phantom1: PhantomData<&'a T>,
    pub(super) _phantom2: PhantomData<A>,
}

impl<A, T: ?Sized> BorrowedMapping<'_, A, T> {
    pub(super) fn as_ptr<U>(&self) -> *const U {
        self.region.start().as_ptr()
    }

    pub(super) fn as_mut_ptr<U>(&self) -> *mut U {
        self.region.start().as_mut_ptr()
    }

    /// See documentation for [`Mapping::borrow_at()`].
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        // The start of the new region should not go beyond the current
        // one and be aligned to `U`.
        let start = self
            .region
            .start()
            .checked_add(byte_off)
            .ok_or(SvsmError::MemOverflow)?;
        if !start.is_aligned_to::<U>() {
            return Err(SvsmError::MemAlign);
        }
        // The remaining size should accomodate an `U`.
        self.region
            .len()
            .checked_sub(byte_off)
            .filter(|len| *len >= size_of::<U>())
            .ok_or(SvsmError::MemOverflow)?;

        let region = MemoryRegion::new(start, size_of::<U>());
        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }

    /// See documentation for [`Mapping::borrow_slice_at()`].
    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        // The start of the new region should not go beyond the current one and
        // be aligned to `U`.
        let start = self
            .region
            .start()
            .checked_add(byte_off)
            .ok_or(SvsmError::ArithOverflow)?;
        if !start.is_aligned_to::<U>() {
            return Err(SvsmError::MemAlign);
        }
        // The remaining size should accomodate `len` instances of `U`.
        let slice_len = len
            .checked_mul(size_of::<U>())
            .ok_or(SvsmError::ArithOverflow)?;
        self.region
            .len()
            .checked_sub(byte_off)
            .filter(|len| *len >= slice_len)
            .ok_or(SvsmError::MemOverflow)?;

        let region = MemoryRegion::new(start, slice_len);
        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }
}

impl<'a, A, T> BorrowedMapping<'a, A, T> {
    /// Creates a borrowed mapping from an already mapped virtual address.
    ///
    /// # Safety
    ///
    /// The caller must verify that the given address is valid for the size
    /// of the type, properly aligned, that the generic `A` corresponds to the
    /// right access type, and that it does not alias memory in a way that would
    /// break Rust's memory model when reading/writing.
    ///
    /// The lifetime of the returned structure is defined by the caller, so
    /// they must also ensure that it does not exceed the lifetime of the actual
    /// mapping in the page table.
    pub unsafe fn from_address(addr: VirtAddr) -> Result<Self, SvsmError> {
        if addr.is_null() {
            return Err(SvsmError::Mem);
        }
        let region = MemoryRegion::new(addr, size_of::<T>());
        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }

    /// Creates a borrowed mapping from an already mapped virtual address as a
    /// dynamically-sized slice.
    ///
    /// # Safety
    ///
    /// The caller must verify that the given address is valid for the size
    /// of the type, properly aligned, that the generic `A` corresponds to the
    /// right access type, and that it does not alias memory in a way that would
    /// break Rust's memory model when reading/writing.
    ///
    /// The lifetime of the returned structure is defined by the caller, so
    /// they must also ensure that it does not exceed the lifetime of the actual
    /// mapping in the page table.
    pub unsafe fn slice_from_address(
        addr: VirtAddr,
        len: usize,
    ) -> Result<BorrowedMapping<'a, A, [T]>, SvsmError> {
        if addr.is_null() {
            return Err(SvsmError::Mem);
        }
        let slice_len = len
            .checked_mul(size_of::<T>())
            .ok_or(SvsmError::ArithOverflow)?;
        let region = MemoryRegion::new(addr, slice_len);
        Ok(BorrowedMapping {
            region,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }
}

impl<A, T> BorrowedMapping<'_, A, [T]> {
    /// Returns the length of the backing slice.
    pub fn len(&self) -> usize {
        self.region.len() / size_of::<T>()
    }

    /// Returns `true` if the backing slice is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<A: MappingRead, T: FromBytes> BorrowedMapping<'_, A, T> {
    /// See documentation for [`ReadableMapping::read()`].
    fn read(&self) -> Result<T, SvsmError> {
        let mut dst = MaybeUninit::<T>::uninit();
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe {
            A::read(self.as_ptr::<T>(), dst.as_mut_ptr(), 1)?;
            Ok(dst.assume_init())
        }
    }
}

impl<A: MappingRead, T: FromBytes> BorrowedMapping<'_, A, [T]> {
    /// See documentation for [`ReadableSliceMapping::read_item()`].
    fn read_item(&self, idx: usize) -> Result<T, SvsmError> {
        if idx >= self.len() {
            return Err(SvsmError::MemOverflow);
        }
        // SAFETY: we just bounds-checked `idx`
        let src = unsafe { self.as_ptr::<T>().add(idx) };
        let mut dst = MaybeUninit::<T>::uninit();
        // SAFETY: backing memory being valid is part of the invariants of this
        // type. Once the destination has been written without errors, it can
        // be assumed to be initialized.
        unsafe {
            A::read(src, dst.as_mut_ptr(), 1)?;
            Ok(dst.assume_init())
        }
    }

    /// See documentation for [`ReadableSliceMapping::read_to()`].
    fn read_to(&self, dst: &mut [T]) -> Result<(), SvsmError> {
        if self.len() != dst.len() {
            return Err(SvsmError::MemOverflow);
        }
        let src = self.as_ptr::<T>();
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe { A::read(src, dst.as_mut_ptr(), dst.len()) }
    }

    /// See documentation for [`ReadableSliceMapping::read_to_vec()`].
    fn read_to_vec(&self) -> Result<Vec<T>, SvsmError> {
        let len = self.len();
        let src = self.as_ptr::<T>();
        let mut dst = Vec::with_capacity(len);
        // SAFETY: backing memory being valid is part of the invariants of this
        // type. The Vec was fully initialized, so setting the length is safe.
        unsafe {
            A::read(src, dst.as_mut_ptr(), len)?;
            dst.set_len(len);
        };
        Ok(dst)
    }
}

impl<A: MappingWrite, T: IntoBytes> BorrowedMapping<'_, A, T> {
    fn write<B>(&mut self, val: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
    {
        let src = val.borrow();
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe { A::write(src, self.as_mut_ptr::<T>(), 1) }?;
        Ok(())
    }
}

impl<A: MappingWrite, T: IntoBytes> BorrowedMapping<'_, A, [T]> {
    fn write_item<B>(&mut self, val: B, idx: usize) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
    {
        if idx >= self.len() {
            return Err(SvsmError::MemOverflow);
        }
        let src = val.borrow();
        // SAFETY: we just bounds-checked `ìdx`.
        let dst = unsafe { self.as_mut_ptr::<T>().add(idx) };
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe { A::write(src, dst, 1) }?;
        Ok(())
    }

    fn write_from(&mut self, src: &[T]) -> Result<(), SvsmError> {
        if self.len() != src.len() {
            return Err(SvsmError::MemOverflow);
        }
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe { A::write(src.as_ptr(), self.as_mut_ptr::<T>(), src.len()) }?;
        Ok(())
    }
}

impl<A: MappingWrite> BorrowedMapping<'_, A, [u8]> {
    /// Fills the backing slice with the given byte.
    pub fn fill(&mut self, val: u8) -> Result<(), SvsmError> {
        // SAFETY: backing memory being valid is part of the invariants of this
        // type.
        unsafe { A::write_bytes(self.as_mut_ptr::<u8>(), self.len(), val) }?;
        Ok(())
    }
}

impl<A, T> Mapping<A, T> for OwnedMapping<A, T>
where
    T: ?Sized,
{
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        self.borrow_at(byte_off)
    }

    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        self.borrow_slice_at(byte_off, len)
    }
}

impl<A, T: ?Sized> Mapping<A, T> for BorrowedMapping<'_, A, T> {
    fn borrow_at<U>(&self, byte_off: usize) -> Result<BorrowedMapping<'_, A, U>, SvsmError> {
        self.borrow_at(byte_off)
    }

    fn borrow_slice_at<U>(
        &self,
        byte_off: usize,
        len: usize,
    ) -> Result<BorrowedMapping<'_, A, [U]>, SvsmError> {
        self.borrow_slice_at(byte_off, len)
    }
}

impl<A, T> ReadableMapping<A, T> for OwnedMapping<A, T>
where
    A: MappingRead,
    T: FromBytes,
{
    fn read(&self) -> Result<T, SvsmError> {
        self.as_borrow().read()
    }
}

impl<A, T> ReadableMapping<A, T> for BorrowedMapping<'_, A, T>
where
    A: MappingRead,
    T: FromBytes,
{
    fn read(&self) -> Result<T, SvsmError> {
        self.read()
    }
}

impl<A, T> WriteableMapping<A, T> for OwnedMapping<A, T>
where
    A: MappingWrite,
    T: IntoBytes,
{
    fn write<B: Borrow<T>>(&mut self, val: B) -> Result<(), SvsmError> {
        self.as_borrow().write(val)
    }
}

impl<A, T> WriteableMapping<A, T> for BorrowedMapping<'_, A, T>
where
    A: MappingWrite,
    T: IntoBytes,
{
    fn write<B: Borrow<T>>(&mut self, val: B) -> Result<(), SvsmError> {
        self.write(val)
    }
}

impl<A, T> ReadableSliceMapping<A, [T]> for OwnedMapping<A, [T]>
where
    A: MappingRead,
    T: FromBytes,
{
    fn read_item(&self, idx: usize) -> Result<T, SvsmError> {
        self.as_borrowed_slice().read_item(idx)
    }

    fn read_to(&self, dst: &mut [T]) -> Result<(), SvsmError> {
        self.as_borrowed_slice().read_to(dst)
    }

    fn read_to_vec(&self) -> Result<Vec<T>, SvsmError> {
        self.as_borrowed_slice().read_to_vec()
    }
}

impl<A, T> ReadableSliceMapping<A, [T]> for BorrowedMapping<'_, A, [T]>
where
    A: MappingRead,
    T: FromBytes,
{
    fn read_item(&self, idx: usize) -> Result<T, SvsmError> {
        self.read_item(idx)
    }

    fn read_to(&self, dst: &mut [T]) -> Result<(), SvsmError> {
        self.read_to(dst)
    }

    fn read_to_vec(&self) -> Result<Vec<T>, SvsmError> {
        self.read_to_vec()
    }
}

impl<A, T> WriteableSliceMapping<A, [T]> for OwnedMapping<A, [T]>
where
    A: MappingWrite,
    T: IntoBytes,
{
    fn write_item<B: Borrow<T>>(&mut self, val: B, idx: usize) -> Result<(), SvsmError> {
        self.as_borrowed_slice().write_item(val, idx)
    }

    fn write_from(&mut self, src: &[T]) -> Result<(), SvsmError> {
        self.as_borrowed_slice().write_from(src)
    }
}

impl<A, T> WriteableSliceMapping<A, [T]> for BorrowedMapping<'_, A, [T]>
where
    A: MappingWrite,
    T: IntoBytes,
{
    fn write_item<B: Borrow<T>>(&mut self, val: B, idx: usize) -> Result<(), SvsmError> {
        self.write_item(val, idx)
    }

    fn write_from(&mut self, src: &[T]) -> Result<(), SvsmError> {
        self.write_from(src)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mm::access::*;
    use crate::mm::PAGE_SIZE;

    #[repr(align(4096))]
    #[derive(Debug, FromBytes, IntoBytes)]
    #[expect(dead_code)]
    struct DataPage([u8; PAGE_SIZE]);

    impl DataPage {
        const fn new() -> Self {
            Self([0xfe; PAGE_SIZE])
        }
    }

    fn get_test_page() -> BorrowedMapping<'static, Local, DataPage> {
        static PAGE: DataPage = DataPage::new();

        let addr = VirtAddr::from(&raw const PAGE);
        // SAFETY: we never write to this address and we never give out
        // references to the variable, so we cannot break aliasing rules.
        unsafe { BorrowedMapping::from_address(addr).unwrap() }
    }

    /// Test different valid and invalid borrows
    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_borrow() {
        let mapping = get_test_page();

        // Within bounds, should work
        mapping.borrow_at::<u8>(PAGE_SIZE - 1).unwrap();
        assert_eq!(
            mapping
                .borrow_slice_at::<u8>(PAGE_SIZE - 1, 1)
                .unwrap()
                .len(),
            1
        );

        // Out of bounds, should fail
        mapping.borrow_at::<u8>(PAGE_SIZE).unwrap_err();
        mapping.borrow_slice_at::<u8>(PAGE_SIZE, 1).unwrap_err();
    }

    /// Test different valid and invalid reads
    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read() {
        let mapping = get_test_page();
        assert_eq!(
            Mapping::borrow::<u8>(&mapping).unwrap().read().unwrap(),
            0xfe
        );
        assert_eq!(
            mapping
                .borrow_at::<u8>(PAGE_SIZE - 1)
                .unwrap()
                .read()
                .unwrap(),
            0xfe
        );
    }

    /// Test different valid and invalid slice reads
    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_slice() {
        let mut dst = [0; PAGE_SIZE];
        let mapping = get_test_page();

        // Read a single element
        {
            assert_eq!(
                mapping
                    .borrow_slice::<u8>(PAGE_SIZE)
                    .unwrap()
                    .read_item(4)
                    .unwrap(),
                0xfe,
            );
            mapping
                .borrow_slice::<u8>(PAGE_SIZE)
                .unwrap()
                .read_item(PAGE_SIZE)
                .unwrap_err();
        }

        // Slice at offset 0
        {
            let page = mapping.borrow_slice::<u8>(PAGE_SIZE).unwrap();
            page.read_to(&mut dst).unwrap();
            assert!(dst.iter().all(|b| *b == 0xfe));
            page.read_to(&mut dst[..PAGE_SIZE - 1]).unwrap_err();
        }

        dst.fill(0);

        // Slice at offset > 0
        {
            let page = mapping.borrow_slice_at::<u8>(256, PAGE_SIZE - 256).unwrap();
            let valid = &mut dst[..PAGE_SIZE - 256];
            assert_eq!(page.len(), valid.len());
            page.read_to(valid).unwrap();
            assert!(valid.iter().all(|b| *b == 0xfe));
            dst[PAGE_SIZE - 256..].iter().all(|b| *b == 0x00);
            page.read_to(&mut dst).unwrap_err();
        }
    }
}
