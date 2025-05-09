// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::mem::{copy_bytes, write_bytes};
use crate::error::SvsmError;
use crate::fs::Buffer;
use crate::locking::SpinLock;
use crate::mm::virt_to_phys;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::utils::{align_down, align_up, zero_mem_region};
use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::{cmp, ptr, slice};

#[cfg(any(test, fuzzing))]
use crate::locking::LockGuard;

/// Represents possible errors that can occur during memory allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// The provided page type is invalid.
    InvalidPageType,
    /// The heap address is invalid.
    InvalidHeapAddress(VirtAddr),
    /// Out of memory error.
    OutOfMemory,
    /// The specified page order is invalid.
    InvalidPageOrder(usize),
    /// The file page has an invalid virtual address.
    InvalidFilePage(VirtAddr),
    /// The page frame number (PFN) is invalid.
    InvalidPfn(usize),
    /// The specified size causes an error when creating the layout.
    InvalidLayout,
}

impl From<AllocError> for SvsmError {
    fn from(err: AllocError) -> Self {
        Self::Alloc(err)
    }
}

/// Maximum order of page allocations (up to 128kb)
pub const MAX_ORDER: usize = 6;

/// Calculates the order of a given size for page allocation.
///
/// # Arguments
///
/// * `size` - The size for which to calculate the order.
///
/// # Returns
///
/// The calculated order.
pub const fn get_order(size: usize) -> usize {
    match size.checked_next_power_of_two() {
        Some(v) => v.ilog2() as usize,
        None => usize::BITS as usize,
    }
    .saturating_sub(PAGE_SHIFT)
}

/// Enum representing the type of a memory page.
#[derive(Clone, Copy, Debug)]
#[repr(u64)]
enum PageType {
    Free = 0,
    Allocated = 1,
    SlabPage = 2,
    Compound = 3,
    // File pages used for file and task data
    File = 4,
    Reserved = (1u64 << PageStorageType::TYPE_SHIFT) - 1,
}

impl TryFrom<u64> for PageType {
    type Error = AllocError;
    fn try_from(val: u64) -> Result<Self, Self::Error> {
        match val {
            v if v == Self::Free as u64 => Ok(Self::Free),
            v if v == Self::Allocated as u64 => Ok(Self::Allocated),
            v if v == Self::SlabPage as u64 => Ok(Self::SlabPage),
            v if v == Self::Compound as u64 => Ok(Self::Compound),
            v if v == Self::File as u64 => Ok(Self::File),
            v if v == Self::Reserved as u64 => Ok(Self::Reserved),
            _ => Err(AllocError::InvalidPageType),
        }
    }
}

/// Storage type of a memory page, including encoding and decoding methods
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct PageStorageType(u64);

impl PageStorageType {
    const TYPE_SHIFT: u64 = 4;
    const TYPE_MASK: u64 = (1u64 << Self::TYPE_SHIFT) - 1;
    const NEXT_SHIFT: u64 = 12;
    const NEXT_MASK: u64 = !((1u64 << Self::NEXT_SHIFT) - 1);
    const ORDER_MASK: u64 = (1u64 << (Self::NEXT_SHIFT - Self::TYPE_SHIFT)) - 1;
    // Slab item sizes are encoded in a u16
    const SLAB_MASK: u64 = 0xffff;

    /// Creates a new [`PageStorageType`] with the specified page type.
    ///
    /// # Arguments
    ///
    /// * `t` - The page type.
    ///
    /// # Returns
    ///
    /// A new instance of [`PageStorageType`].
    const fn new(t: PageType) -> Self {
        Self(t as u64)
    }

    /// Encodes the order of the page.
    ///
    /// # Arguments
    ///
    /// * `order` - The order to encode.
    ///
    /// # Returns
    ///
    /// The updated [`PageStorageType`].
    fn encode_order(self, order: usize) -> Self {
        Self(self.0 | ((order as u64) & Self::ORDER_MASK) << Self::TYPE_SHIFT)
    }

    /// Encodes the index of the next page.
    ///
    /// # Arguments
    ///
    /// * `next_page` - The index of the next page.
    ///
    /// # Returns
    ///
    /// The updated [`PageStorageType`].
    fn encode_next(self, next_page: usize) -> Self {
        Self(self.0 | (next_page as u64) << Self::NEXT_SHIFT)
    }

    /// Encodes the virtual address of the slab
    ///
    /// # Arguments
    ///
    /// * `slab` - slab virtual address
    ///
    /// # Returns
    ///
    /// The updated [`PageStorageType`]
    fn encode_slab(self, slab: u64) -> Self {
        let item_size = slab & Self::SLAB_MASK;
        Self(self.0 | (item_size << Self::TYPE_SHIFT))
    }

    /// Encodes the reference count.
    ///
    /// # Arguments
    ///
    /// * `refcount` - The reference count to encode.
    ///
    /// # Returns
    ///
    /// The updated [`PageStorageType`].
    fn encode_refcount(self, refcount: u64) -> Self {
        Self(self.0 | refcount << Self::TYPE_SHIFT)
    }

    /// Decodes the order of the page.
    fn decode_order(&self) -> usize {
        ((self.0 >> Self::TYPE_SHIFT) & Self::ORDER_MASK) as usize
    }

    /// Decodes the index of the next page.
    fn decode_next(&self) -> usize {
        ((self.0 & Self::NEXT_MASK) >> Self::NEXT_SHIFT) as usize
    }

    /// Decodes the slab
    fn decode_slab(&self) -> u64 {
        (self.0 >> Self::TYPE_SHIFT) & Self::SLAB_MASK
    }

    /// Decodes the reference count.
    fn decode_refcount(&self) -> u64 {
        self.0 >> Self::TYPE_SHIFT
    }

    /// Retrieves the page type from the [`PageStorageType`].
    fn page_type(&self) -> Result<PageType, AllocError> {
        PageType::try_from(self.0 & Self::TYPE_MASK)
    }
}

/// Struct representing information about a free memory page.
#[derive(Clone, Copy, Debug)]
struct FreeInfo {
    /// Index of the next free page.
    next_page: usize,
    /// Order of the free page.
    order: usize,
}

impl FreeInfo {
    /// Encodes the [`FreeInfo`] into a [`PageStorageType`].
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Free)
            .encode_order(self.order)
            .encode_next(self.next_page)
    }

    /// Decodes a [`FreeInfo`] into a [`PageStorageType`].
    fn decode(mem: PageStorageType) -> Self {
        let next_page = mem.decode_next();
        let order = mem.decode_order();
        Self { next_page, order }
    }
}

/// Struct representing information about an allocated memory page.
#[derive(Clone, Copy, Debug)]
struct AllocatedInfo {
    order: usize,
}

impl AllocatedInfo {
    /// Encodes the [`AllocatedInfo`] into a [`PageStorageType`].
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Allocated).encode_order(self.order)
    }

    /// Decodes a [`PageStorageType`] into an [`AllocatedInfo`].
    fn decode(mem: PageStorageType) -> Self {
        let order = mem.decode_order();
        Self { order }
    }
}

/// Struct representing information about a slab memory page.
#[derive(Clone, Copy, Debug)]
struct SlabPageInfo {
    item_size: u64,
}

impl SlabPageInfo {
    /// Encodes the [`SlabPageInfo`] into a [`PageStorageType`].
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::SlabPage).encode_slab(self.item_size)
    }

    /// Decodes a [`PageStorageType`] into a [`SlabPageInfo`].
    fn decode(mem: PageStorageType) -> Self {
        let item_size = mem.decode_slab();
        Self { item_size }
    }
}

/// Struct representing information about a compound memory page.
#[derive(Clone, Copy, Debug)]
struct CompoundInfo {
    order: usize,
}

impl CompoundInfo {
    /// Encodes the [`CompoundInfo`] into a [`PageStorageType`].
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Compound).encode_order(self.order)
    }

    /// Decodes a [`PageStorageType`] into a [`CompoundInfo`].
    fn decode(mem: PageStorageType) -> Self {
        let order = mem.decode_order();
        Self { order }
    }
}

/// Struct representing information about a reserved memory page.
#[derive(Clone, Copy, Debug)]
struct ReservedInfo;

impl ReservedInfo {
    /// Encodes the [`ReservedInfo`] into a [`PageStorageType`].
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Reserved)
    }

    /// Decodes a [`PageStorageType`] into a [`ReservedInfo`].
    fn decode(_mem: PageStorageType) -> Self {
        Self
    }
}

/// Struct representing information about a file memory page.
#[derive(Clone, Copy, Debug)]
struct FileInfo {
    /// Reference count of the file page.
    ref_count: u64,
}

impl FileInfo {
    /// Creates a new [`FileInfo`] with the specified reference count.
    const fn new(ref_count: u64) -> Self {
        Self { ref_count }
    }

    /// Encodes the [`FileInfo`] into a [`PageStorageType`].
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::File).encode_refcount(self.ref_count)
    }

    /// Decodes a [`PageStorageType`] into a [`FileInfo`].
    fn decode(mem: PageStorageType) -> Self {
        let ref_count = mem.decode_refcount();
        Self { ref_count }
    }
}

/// Enum representing different types of page information.
#[derive(Clone, Copy, Debug)]
enum PageInfo {
    Free(FreeInfo),
    Allocated(AllocatedInfo),
    Slab(SlabPageInfo),
    Compound(CompoundInfo),
    File(FileInfo),
    Reserved(ReservedInfo),
}

impl PageInfo {
    /// Converts [`PageInfo`] into a [`PageStorageType`].
    fn to_mem(self) -> PageStorageType {
        match self {
            Self::Free(fi) => fi.encode(),
            Self::Allocated(ai) => ai.encode(),
            Self::Slab(si) => si.encode(),
            Self::Compound(ci) => ci.encode(),
            Self::File(fi) => fi.encode(),
            Self::Reserved(ri) => ri.encode(),
        }
    }

    /// Converts a [`PageStorageType`] into [`PageInfo`].
    fn from_mem(mem: PageStorageType) -> Self {
        let Ok(page_type) = mem.page_type() else {
            panic!("Unknown page type in {:?}", mem);
        };

        match page_type {
            PageType::Free => Self::Free(FreeInfo::decode(mem)),
            PageType::Allocated => Self::Allocated(AllocatedInfo::decode(mem)),
            PageType::SlabPage => Self::Slab(SlabPageInfo::decode(mem)),
            PageType::Compound => Self::Compound(CompoundInfo::decode(mem)),
            PageType::File => Self::File(FileInfo::decode(mem)),
            PageType::Reserved => Self::Reserved(ReservedInfo::decode(mem)),
        }
    }
}

/// Represents info about allocated and free pages in different orders.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemInfo {
    total_pages: [usize; MAX_ORDER],
    free_pages: [usize; MAX_ORDER],
}

/// Memory region with its physical/virtual addresses, page count, as well
/// as other details.
#[derive(Debug, Default)]
struct MemoryRegion {
    start_phys: PhysAddr,
    start_virt: VirtAddr,
    page_count: usize,
    nr_pages: [usize; MAX_ORDER],
    next_page: [usize; MAX_ORDER],
    free_pages: [usize; MAX_ORDER],
}

impl MemoryRegion {
    /// Creates a new [`MemoryRegion`] with default values.
    const fn new() -> Self {
        Self {
            start_phys: PhysAddr::null(),
            start_virt: VirtAddr::null(),
            page_count: 0,
            nr_pages: [0; MAX_ORDER],
            next_page: [0; MAX_ORDER],
            free_pages: [0; MAX_ORDER],
        }
    }

    /// Converts a physical address within this memory region to a virtual address.
    #[expect(dead_code)]
    fn phys_to_virt(&self, paddr: PhysAddr) -> Option<VirtAddr> {
        let end_phys = self.start_phys + (self.page_count * PAGE_SIZE);

        if paddr < self.start_phys || paddr >= end_phys {
            // For the initial stage2 identity mapping, the root page table
            // pages are static and outside of the heap memory region.
            if VirtAddr::from(self.start_phys.bits()) == self.start_virt {
                return Some(VirtAddr::from(paddr.bits()));
            }
            return None;
        }

        let offset = paddr - self.start_phys;

        Some(self.start_virt + offset)
    }

    /// Converts a virtual address to a physical address within the memory region.
    #[expect(dead_code)]
    fn virt_to_phys(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let offset = self.get_virt_offset(vaddr)?;
        Some(self.start_phys + offset)
    }

    /// Gets a mutable pointer to the page information for a given page frame
    /// number.
    ///
    /// # Safety
    ///
    /// The caller must provide a valid pfn, otherwise the returned pointer is
    /// undefined, as the compiler is allowed to optimize assuming there will
    /// be no arithmetic overflows.
    unsafe fn page_info_mut_ptr(&mut self, pfn: usize) -> *mut PageStorageType {
        unsafe { self.start_virt.as_mut_ptr::<PageStorageType>().add(pfn) }
    }

    /// Gets a pointer to the page information for a given page frame number.
    ///
    /// # Safety
    ///
    /// The caller must provide a valid pfn, otherwise the returned pointer is
    /// undefined, as the compiler is allowed to optimize assuming there will
    /// be no arithmetic overflows.
    unsafe fn page_info_ptr(&self, pfn: usize) -> *const PageStorageType {
        unsafe { self.start_virt.as_ptr::<PageStorageType>().add(pfn) }
    }

    /// Checks if a page frame number is valid.
    ///
    /// # Panics
    ///
    /// Panics if the page frame number is invalid.
    fn check_pfn(&self, pfn: usize) {
        if pfn >= self.page_count {
            panic!("Invalid Page Number {}", pfn);
        }
    }

    /// Calculates the end virtual address of the memory region.
    fn end_virt(&self) -> VirtAddr {
        self.start_virt + (self.page_count * PAGE_SIZE)
    }

    /// Writes page information for a given page frame number.
    fn write_page_info(&mut self, pfn: usize, pi: PageInfo) {
        self.check_pfn(pfn);

        let info: PageStorageType = pi.to_mem();
        // SAFETY: we have checked that the pfn is valid via check_pfn() above.
        unsafe { self.page_info_mut_ptr(pfn).write(info) };
    }

    /// Reads page information for a given page frame number.
    fn read_page_info(&self, pfn: usize) -> PageInfo {
        self.check_pfn(pfn);

        // SAFETY: we have checked that the pfn is valid via check_pfn() above.
        let info = unsafe { self.page_info_ptr(pfn).read() };
        PageInfo::from_mem(info)
    }

    /// Gets the virtual offset of a virtual address within the memory region.
    fn get_virt_offset(&self, vaddr: VirtAddr) -> Option<usize> {
        (self.start_virt <= vaddr && vaddr < self.end_virt()).then(|| vaddr - self.start_virt)
    }

    /// Gets the page frame number for a given virtual address.
    fn get_pfn(&self, vaddr: VirtAddr) -> Result<usize, AllocError> {
        self.get_virt_offset(vaddr)
            .map(|off| off / PAGE_SIZE)
            .ok_or(AllocError::InvalidHeapAddress(vaddr))
    }

    /// Gets the next available page frame number for a given order.
    fn get_next_page(&mut self, order: usize) -> Result<usize, AllocError> {
        let pfn = self.next_page[order];

        if pfn == 0 {
            return Err(AllocError::OutOfMemory);
        }

        let pg = self.read_page_info(pfn);
        let PageInfo::Free(fi) = pg else {
            panic!(
                "Unexpected page type in MemoryRegion::get_next_page() {:?}",
                pg
            );
        };

        self.next_page[order] = fi.next_page;

        self.free_pages[order] -= 1;

        Ok(pfn)
    }

    /// Marks a compound page and updates page information for neighboring pages.
    fn mark_compound_page(&mut self, pfn: usize, order: usize) {
        let nr_pages: usize = 1 << order;
        let compound = PageInfo::Compound(CompoundInfo { order });
        for i in 1..nr_pages {
            self.write_page_info(pfn + i, compound);
        }
    }

    /// Initializes a compound page with given page frame numbers and order.
    fn init_compound_page(&mut self, pfn: usize, order: usize, next_pfn: usize) {
        let head = PageInfo::Free(FreeInfo {
            next_page: next_pfn,
            order,
        });
        self.write_page_info(pfn, head);
        self.mark_compound_page(pfn, order);
    }

    /// Splits a page into two pages of the next lower order.
    fn split_page(&mut self, pfn: usize, order: usize) -> Result<(), AllocError> {
        if !(1..MAX_ORDER).contains(&order) {
            return Err(AllocError::InvalidPageOrder(order));
        }

        let new_order = order - 1;
        let pfn1 = pfn;
        let pfn2 = pfn + (1usize << new_order);

        let next_pfn = self.next_page[new_order];
        self.init_compound_page(pfn1, new_order, pfn2);
        self.init_compound_page(pfn2, new_order, next_pfn);
        self.next_page[new_order] = pfn1;

        // Do the accounting
        self.nr_pages[order] -= 1;
        self.nr_pages[new_order] += 2;
        self.free_pages[new_order] += 2;

        Ok(())
    }

    /// Refills the free page list for a given order.
    fn refill_page_list(&mut self, order: usize) -> Result<(), AllocError> {
        let next_page = *self
            .next_page
            .get(order)
            .ok_or(AllocError::InvalidPageOrder(order))?;
        if next_page != 0 {
            return Ok(());
        }

        self.refill_page_list(order + 1)?;
        let pfn = self.get_next_page(order + 1)?;
        self.split_page(pfn, order + 1)
    }

    /// Allocates pages with a specific order and page information.
    fn allocate_pages_info(&mut self, order: usize, pg: PageInfo) -> Result<VirtAddr, AllocError> {
        self.refill_page_list(order)?;
        let pfn = self.get_next_page(order)?;
        self.write_page_info(pfn, pg);
        Ok(self.start_virt + (pfn * PAGE_SIZE))
    }

    /// Allocates pages with a specific order.
    fn allocate_pages(&mut self, order: usize) -> Result<VirtAddr, AllocError> {
        let pg = PageInfo::Allocated(AllocatedInfo { order });
        self.allocate_pages_info(order, pg)
    }

    /// Allocates a single page.
    fn allocate_page(&mut self) -> Result<VirtAddr, AllocError> {
        self.allocate_pages(0)
    }

    /// Allocates a zeroed page.
    fn allocate_zeroed_page(&mut self) -> Result<VirtAddr, AllocError> {
        let vaddr = self.allocate_page()?;

        // SAFETY: we trust allocate_page() to return a pointer to a valid
        // page. vaddr + PAGE_SIZE also correctly points to the end of the
        // page.
        unsafe {
            zero_mem_region(vaddr, vaddr + PAGE_SIZE);
        }

        Ok(vaddr)
    }

    /// Allocates a slab page.
    fn allocate_slab_page(&mut self, item_size: u16) -> Result<VirtAddr, AllocError> {
        self.refill_page_list(0)?;

        let pfn = self.get_next_page(0)?;
        let pg = PageInfo::Slab(SlabPageInfo {
            item_size: u64::from(item_size),
        });
        self.write_page_info(pfn, pg);
        Ok(self.start_virt + (pfn * PAGE_SIZE))
    }

    /// Allocates a file page with initial reference count.
    fn allocate_file_page(&mut self) -> Result<VirtAddr, AllocError> {
        let pg = PageInfo::File(FileInfo::new(1));
        self.allocate_pages_info(0, pg)
    }

    /// Gets a file page and increments its reference count.
    fn get_file_page(&mut self, vaddr: VirtAddr) -> Result<(), AllocError> {
        let pfn = self.get_pfn(vaddr)?;
        let page = self.read_page_info(pfn);
        let PageInfo::File(mut fi) = page else {
            return Err(AllocError::InvalidFilePage(vaddr));
        };

        assert!(fi.ref_count > 0);
        fi.ref_count += 1;
        self.write_page_info(pfn, PageInfo::File(fi));

        Ok(())
    }

    /// Releases a file page and decrements its reference count.
    fn put_file_page(&mut self, vaddr: VirtAddr) -> Result<(), AllocError> {
        let pfn = self.get_pfn(vaddr)?;
        let page = self.read_page_info(pfn);
        let PageInfo::File(mut fi) = page else {
            return Err(AllocError::InvalidFilePage(vaddr));
        };

        fi.ref_count = fi
            .ref_count
            .checked_sub(1)
            .expect("page refcount underflow");
        if fi.ref_count > 0 {
            self.write_page_info(pfn, PageInfo::File(fi));
        } else {
            self.free_page(vaddr)
        }

        Ok(())
    }

    /// Finds the neighboring page frame number for a compound page.
    fn compound_neighbor(&self, pfn: usize, order: usize) -> Result<usize, AllocError> {
        if order >= MAX_ORDER - 1 {
            return Err(AllocError::InvalidPageOrder(order));
        }

        assert_eq!(pfn & ((1usize << order) - 1), 0);
        let pfn = pfn ^ (1usize << order);
        if pfn >= self.page_count {
            return Err(AllocError::InvalidPfn(pfn));
        }

        Ok(pfn)
    }

    /// Merges two pages of the same order into a new compound page.
    fn merge_pages(&mut self, pfn1: usize, pfn2: usize, order: usize) -> Result<usize, AllocError> {
        if order >= MAX_ORDER - 1 {
            return Err(AllocError::InvalidPageOrder(order));
        }

        let nr_pages: usize = 1 << (order + 1);
        let pfn = pfn1.min(pfn2);

        // Write new compound head
        let pg = PageInfo::Allocated(AllocatedInfo { order: order + 1 });
        self.write_page_info(pfn, pg);

        // Write compound pages
        let pg = PageInfo::Compound(CompoundInfo { order: order + 1 });
        for i in 1..nr_pages {
            self.write_page_info(pfn + i, pg);
        }

        // Do the accounting - none of the pages is free yet, so free_pages is
        // not updated here.
        self.nr_pages[order] -= 2;
        self.nr_pages[order + 1] += 1;

        Ok(pfn)
    }

    /// Gets the next free page frame number from the free list.
    fn next_free_pfn(&self, pfn: usize, order: usize) -> usize {
        let page = self.read_page_info(pfn);
        let PageInfo::Free(fi) = page else {
            panic!("Unexpected page type in free-list for order {}", order);
        };

        fi.next_page
    }

    /// Allocates a specific page frame number (`pfn`) within a given order.
    /// If the page frame number is not found or is already allocated, an error
    /// is returned. If the requested page frame number is the first in the
    /// list, it is marked as allocated, and the next page in the list becomes
    /// the new first page.
    ///
    /// # Panics
    ///
    /// Panics if `order` is greater than [`MAX_ORDER`].
    fn allocate_pfn(&mut self, pfn: usize, order: usize) -> Result<(), AllocError> {
        let first_pfn = self.next_page[order];

        // Handle special cases first
        if first_pfn == 0 {
            // No pages for that order
            return Err(AllocError::OutOfMemory);
        } else if first_pfn == pfn {
            // Requested pfn is first in list
            self.get_next_page(order).unwrap();
            return Ok(());
        }

        // Now walk the list
        let mut old_pfn = first_pfn;
        loop {
            let current_pfn = self.next_free_pfn(old_pfn, order);
            if current_pfn == 0 {
                return Err(AllocError::OutOfMemory);
            }

            if current_pfn != pfn {
                old_pfn = current_pfn;
                continue;
            }

            let next_pfn = self.next_free_pfn(current_pfn, order);
            let pg = PageInfo::Free(FreeInfo {
                next_page: next_pfn,
                order,
            });
            self.write_page_info(old_pfn, pg);

            let pg = PageInfo::Allocated(AllocatedInfo { order });
            self.write_page_info(current_pfn, pg);

            self.free_pages[order] -= 1;

            return Ok(());
        }
    }

    /// Frees a raw page by updating the free list and marking it as a free page.
    ///
    /// # Panics
    ///
    /// Panics if `order` is greater than [`MAX_ORDER`].
    fn free_page_raw(&mut self, pfn: usize, order: usize) {
        let old_next = self.next_page[order];
        let pg = PageInfo::Free(FreeInfo {
            next_page: old_next,
            order,
        });

        self.write_page_info(pfn, pg);
        self.next_page[order] = pfn;

        self.free_pages[order] += 1;
    }

    /// Attempts to merge a given page with its neighboring page.
    /// If successful, returns the new page frame number after merging.
    /// If unsuccessful, the page remains unmerged, and an error is returned.
    fn try_to_merge_page(&mut self, pfn: usize, order: usize) -> Result<usize, AllocError> {
        let neighbor_pfn = self.compound_neighbor(pfn, order)?;
        let neighbor_page = self.read_page_info(neighbor_pfn);

        let PageInfo::Free(fi) = neighbor_page else {
            return Err(AllocError::InvalidPfn(neighbor_pfn));
        };

        if fi.order != order {
            return Err(AllocError::InvalidPageOrder(fi.order));
        }

        self.allocate_pfn(neighbor_pfn, order)?;

        let new_pfn = self.merge_pages(pfn, neighbor_pfn, order)?;

        Ok(new_pfn)
    }

    /// Frees a page of a specific order. If merging is successful, it
    /// continues merging until merging is no longer possible. If merging
    /// fails, the page is marked as a free page.
    fn free_page_order(&mut self, pfn: usize, order: usize) {
        match self.try_to_merge_page(pfn, order) {
            Err(_) => {
                self.free_page_raw(pfn, order);
            }
            Ok(new_pfn) => {
                self.free_page_order(new_pfn, order + 1);
            }
        }
    }

    /// Frees a page based on its virtual address, determining the page
    /// order and freeing accordingly.
    fn free_page(&mut self, vaddr: VirtAddr) {
        let Ok(pfn) = self.get_pfn(vaddr) else {
            return;
        };

        let res = self.read_page_info(pfn);

        match res {
            PageInfo::Allocated(ai) => {
                self.free_page_order(pfn, ai.order);
            }
            PageInfo::Slab(_si) => {
                self.free_page_order(pfn, 0);
            }
            PageInfo::Compound(ci) => {
                let mask = (1usize << ci.order) - 1;
                let start_pfn = pfn & !mask;
                self.free_page_order(start_pfn, ci.order);
            }
            PageInfo::File(_) => {
                self.free_page_order(pfn, 0);
            }
            _ => {
                panic!("Unexpected page type in MemoryRegion::free_page()");
            }
        }
    }

    /// Retrieves information about memory, including total and free pages
    /// in different orders.
    fn memory_info(&self) -> MemInfo {
        MemInfo {
            total_pages: self.nr_pages,
            free_pages: self.free_pages,
        }
    }

    /// Initializes memory by marking certain pages as reserved and the rest
    /// as allocated. It then frees all pages and organizes them into their
    /// respective order buckets.
    fn init_memory(&mut self) {
        let size = size_of::<PageStorageType>();
        let meta_pages = align_up(self.page_count * size, PAGE_SIZE) / PAGE_SIZE;

        /* Mark page storage as reserved */
        for i in 0..meta_pages {
            let pg = PageInfo::Reserved(ReservedInfo);
            self.write_page_info(i, pg);
        }

        /* Mark all pages as allocated */
        for i in meta_pages..self.page_count {
            let pg = PageInfo::Allocated(AllocatedInfo { order: 0 });
            self.write_page_info(i, pg);
        }

        /* Now free all pages.  Any runs of pages aligned to the maximum order
         * will be freed directly into the maximum order bucket, and all other
         * pages will be freed individually so the correct orders can be
         * generated */
        let alignment = 1 << (MAX_ORDER - 1);
        let first_aligned_page = align_up(meta_pages, alignment);
        let last_aligned_page = align_down(self.page_count, alignment);

        if first_aligned_page < last_aligned_page {
            self.nr_pages[MAX_ORDER - 1] += (last_aligned_page - first_aligned_page) / alignment;
            for i in (first_aligned_page..last_aligned_page).step_by(alignment) {
                self.mark_compound_page(i, MAX_ORDER - 1);
                self.free_page_raw(i, MAX_ORDER - 1);
            }

            if first_aligned_page < self.page_count {
                self.nr_pages[0] += first_aligned_page - meta_pages;
                for i in meta_pages..first_aligned_page {
                    self.free_page_order(i, 0);
                }
            }

            if last_aligned_page > meta_pages {
                self.nr_pages[0] += self.page_count - last_aligned_page;
                for i in last_aligned_page..self.page_count {
                    self.free_page_order(i, 0);
                }
            }
        } else {
            // Special case: Memory region size smaller than a MAX_ORDER allocation
            self.nr_pages[0] = self.page_count - meta_pages;
            for i in meta_pages..self.page_count {
                self.free_page_order(i, 0);
            }
        }
    }
}

/// Represents a reference to a memory page, holding both virtual and
/// physical addresses.
#[derive(Debug)]
pub struct PageRef {
    virt_addr: VirtAddr,
    phys_addr: PhysAddr,
}

impl PageRef {
    /// Allocate a reference-counted file page.
    pub fn new() -> Result<Self, SvsmError> {
        let virt_addr = allocate_file_page()?;
        let phys_addr = virt_to_phys(virt_addr);

        Ok(Self {
            virt_addr,
            phys_addr,
        })
    }

    /// Returns the virtual address of the memory page.
    pub fn virt_addr(&self) -> VirtAddr {
        self.virt_addr
    }

    /// Returns the physical address of the memory page.
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    pub fn try_copy_page(&self) -> Result<Self, SvsmError> {
        let virt_addr = allocate_file_page()?;

        let src = self.virt_addr.bits();
        let dst = virt_addr.bits();
        let size = PAGE_SIZE;
        unsafe {
            // SAFETY: `src` and `dst` are both valid.
            copy_bytes(src, dst, size);
        }

        Ok(PageRef {
            virt_addr,
            phys_addr: virt_to_phys(virt_addr),
        })
    }

    pub fn write(&self, offset: usize, buf: &[u8]) {
        assert!(offset.checked_add(buf.len()).unwrap() <= PAGE_SIZE);

        let src = buf.as_ptr() as usize;
        let dst = self.virt_addr.bits() + offset;
        let size = buf.len();
        unsafe {
            // SAFETY: `src` and `dst` are both valid.
            copy_bytes(src, dst, size);
        }
    }

    pub fn read(&self, offset: usize, buf: &mut [u8]) {
        assert!(offset.checked_add(buf.len()).unwrap() <= PAGE_SIZE);

        let src = self.virt_addr.bits() + offset;
        let dst = buf.as_mut_ptr() as usize;
        let size = buf.len();
        unsafe {
            // SAFETY: `src` and `dst` are both valid.
            copy_bytes(src, dst, size);
        }
    }

    /// Write to page from [`Buffer`] object
    ///
    /// Arguments:
    ///
    /// - `buffer`: Reference to buffer object.
    /// - `buffer_offset`: Offset into the buffer to start writing from.
    /// - `page_offset`: Offset into the page where to start writing to.
    /// - `size`: Number of bytes to copy. `page_offset + size` must be `<=
    //     PAGE_SIZE`.
    ///
    /// # Returns:
    ///
    /// Number of bytes written on success, [`SvsmError`] on failure.
    pub fn copy_from_buffer(
        &self,
        buffer: &dyn Buffer,
        buffer_offset: usize,
        page_offset: usize,
        size: usize,
    ) -> Result<usize, SvsmError> {
        assert!(page_offset.checked_add(size).unwrap() <= PAGE_SIZE);
        assert!(buffer_offset.checked_add(size).unwrap() <= buffer.size());

        let safe_size = cmp::min(PAGE_SIZE - page_offset, size);

        // SAFETY: The calculations and asserts above make sure no data is
        // written outside of the page boundaries.
        let dst_slice: &mut [u8] = unsafe {
            slice::from_raw_parts_mut(
                self.virt_addr.const_add(page_offset).as_mut_ptr(),
                safe_size,
            )
        };
        buffer.read_buffer(dst_slice, buffer_offset)
    }

    /// Read from page to [`Buffer`] object
    ///
    /// Arguments:
    ///
    /// - `buffer`: Reference to buffer object.
    /// - `buffer_offset`: Offset into the buffer to start writing to.
    /// - `page_offset`: Offset into the page where to start reading from.
    /// - `size`: Number of bytes to copy. `page_offset + size` must be `<=
    //     PAGE_SIZE`.
    ///
    /// # Returns:
    ///
    /// Number of bytes read on success, [`SvsmError`] on failure.
    pub fn copy_to_buffer(
        &self,
        buffer: &mut dyn Buffer,
        buffer_offset: usize,
        page_offset: usize,
        size: usize,
    ) -> Result<usize, SvsmError> {
        assert!(page_offset.checked_add(size).unwrap() <= PAGE_SIZE);
        assert!(buffer_offset.checked_add(size).unwrap() <= buffer.size());

        let safe_size = cmp::min(PAGE_SIZE - page_offset, size);

        // SAFETY: The calculations and asserts above make sure no data is read
        // outside of the page boundaries.
        let src_slice: &[u8] = unsafe {
            slice::from_raw_parts(self.virt_addr.const_add(page_offset).as_ptr(), safe_size)
        };
        buffer.write_buffer(src_slice, buffer_offset)
    }

    pub fn fill(&self, offset: usize, value: u8) {
        let dst = self.virt_addr.bits() + offset;
        let size = PAGE_SIZE.checked_sub(offset).unwrap();

        unsafe {
            // SAFETY: `dst` is valid.
            write_bytes(dst, size, value);
        }
    }
}

impl Clone for PageRef {
    /// Clones the [`PageRef`] instance, obtaining a new reference to the same memory page.
    fn clone(&self) -> Self {
        get_file_page(self.virt_addr).expect("Failed to get page reference");
        PageRef {
            virt_addr: self.virt_addr,
            phys_addr: self.phys_addr,
        }
    }
}

impl Drop for PageRef {
    /// Drops the [`PageRef`] instance, decreasing the reference count for
    /// the associated memory page.
    fn drop(&mut self) {
        put_file_page(self.virt_addr).expect("Failed to drop page reference");
    }
}

/// Prints memory information based on the provided [`MemInfo`] structure.
///
/// # Arguments
///
/// * `info` - Reference to [`MemInfo`] structure containing memory information.
pub fn print_memory_info(info: &MemInfo) {
    let mut pages_4k = 0;
    let mut free_pages_4k = 0;

    for i in 0..MAX_ORDER {
        let nr_4k_pages: usize = 1 << i;
        log::info!(
            "Order-{:#02}: total pages: {:#5} free pages: {:#5}",
            i,
            info.total_pages[i],
            info.free_pages[i]
        );
        pages_4k += info.total_pages[i] * nr_4k_pages;
        free_pages_4k += info.free_pages[i] * nr_4k_pages;
    }

    log::info!(
        "Total memory: {}KiB free memory: {}KiB",
        (pages_4k * PAGE_SIZE) / 1024,
        (free_pages_4k * PAGE_SIZE) / 1024
    );
}

/// Static spinlock-protected instance of [`MemoryRegion`] representing the
/// root memory region.
static ROOT_MEM: SpinLock<MemoryRegion> = SpinLock::new(MemoryRegion::new());

/// Allocates a single memory page from the root memory region.
///
/// # Returns
///
/// Result containing the virtual address of the allocated page or an
/// `SvsmError` if allocation fails.
pub fn allocate_page() -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_page()?)
}

/// Allocates multiple memory pages with a specified order from the root
/// memory region.
///
/// # Arguments
///
/// * `order` - Order of the allocation, determining the number of pages (2^order).
///
/// # Returns
///
/// Result containing the virtual address of the allocated pages or an
/// `SvsmError` if allocation fails.
pub fn allocate_pages(order: usize) -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_pages(order)?)
}

/// Allocate a slab page.
///
/// # Arguments
///
/// `slab` - slab virtual address
///
/// # Returns
///
/// Result containing the virtual address of the allocated slab page or an
/// `SvsmError` if allocation fails.
pub fn allocate_slab_page(item_size: u16) -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_slab_page(item_size)?)
}

/// Allocate a zeroed page.
///
/// # Returns
///
/// Result containing the virtual address of the allocated zeroed page or an
/// `SvsmError` if allocation fails.
pub fn allocate_zeroed_page() -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_zeroed_page()?)
}

/// Allocate a file page.
///
/// # Returns
///
/// Result containing the virtual address of the allocated file page or an
/// `SvsmError` if allocation fails.
pub fn allocate_file_page() -> Result<VirtAddr, SvsmError> {
    let vaddr = ROOT_MEM.lock().allocate_file_page()?;

    // SAFETY: we trust allocate_file_page() to return a pointer to a valid
    // page. vaddr + PAGE_SIZE also correctly points to the end of the
    // page.
    unsafe {
        zero_mem_region(vaddr, vaddr + PAGE_SIZE);
    }

    Ok(vaddr)
}

fn get_file_page(vaddr: VirtAddr) -> Result<(), SvsmError> {
    Ok(ROOT_MEM.lock().get_file_page(vaddr)?)
}

fn put_file_page(vaddr: VirtAddr) -> Result<(), SvsmError> {
    Ok(ROOT_MEM.lock().put_file_page(vaddr)?)
}

/// Free the page at the given virtual address.
pub fn free_page(vaddr: VirtAddr) {
    ROOT_MEM.lock().free_page(vaddr)
}

/// Retrieve information about the root memory
pub fn memory_info() -> MemInfo {
    ROOT_MEM.lock().memory_info()
}

/// Represents a slab memory page, used for efficient allocation of
/// fixed-size objects.
#[derive(Debug, Default)]
struct SlabPage<const N: u16> {
    vaddr: VirtAddr,
    free: u16,
    used_bitmap: [u64; 2],
    next_page: VirtAddr,
}

impl<const N: u16> SlabPage<N> {
    /// Creates a new [`SlabPage`] instance with default values.
    const fn new() -> Self {
        assert!(N <= (PAGE_SIZE / 2) as u16);
        Self {
            vaddr: VirtAddr::null(),
            free: 0,
            used_bitmap: [0; 2],
            next_page: VirtAddr::null(),
        }
    }

    /// Initialize the [`SlabPage`].
    fn init(&mut self) -> Result<(), AllocError> {
        if !self.vaddr.is_null() {
            return Ok(());
        }
        let vaddr = ROOT_MEM.lock().allocate_slab_page(N)?;
        self.vaddr = vaddr;
        self.free = self.get_capacity();

        Ok(())
    }

    /// Free the memory (destroy) the [`SlabPage`]
    #[expect(clippy::needless_pass_by_ref_mut)]
    fn destroy(&mut self) {
        if self.vaddr.is_null() {
            return;
        }

        free_page(self.vaddr);
    }

    /// Get the capacity of the [`SlabPage`]
    const fn get_capacity(&self) -> u16 {
        (PAGE_SIZE as u16) / N
    }

    fn get_free(&self) -> u16 {
        self.free
    }

    /// Get the virtual address of the next [`SlabPage`]
    fn get_next_page(&self) -> VirtAddr {
        self.next_page
    }

    fn set_next_page(&mut self, next_page: VirtAddr) {
        self.next_page = next_page;
    }

    fn allocate(&mut self) -> Result<VirtAddr, AllocError> {
        if self.free == 0 {
            return Err(AllocError::OutOfMemory);
        }

        for i in 0..self.get_capacity() {
            let idx = (i / 64) as usize;
            let mask = 1u64 << (i % 64);

            if self.used_bitmap[idx] & mask == 0 {
                self.used_bitmap[idx] |= mask;
                self.free -= 1;
                return Ok(self.vaddr + ((N * i) as usize));
            }
        }

        Err(AllocError::OutOfMemory)
    }

    fn free(&mut self, vaddr: VirtAddr) -> Result<(), AllocError> {
        if vaddr < self.vaddr || vaddr >= self.vaddr + PAGE_SIZE {
            return Err(AllocError::InvalidHeapAddress(vaddr));
        }

        let item_size = N as usize;
        let offset = vaddr - self.vaddr;
        let i = offset / item_size;
        let idx = i / 64;
        let mask = 1u64 << (i % 64);

        self.used_bitmap[idx] &= !mask;
        self.free += 1;

        Ok(())
    }
}

/// Represents common information shared among multiple slab pages.
#[derive(Debug, Default)]
#[repr(align(16))]
struct SlabCommon<const N: u16> {
    capacity: u32,
    free: u32,
    pages: u32,
    full_pages: u32,
    free_pages: u32,
    page: SlabPage<N>,
}

impl<const N: u16> SlabCommon<N> {
    const fn new() -> Self {
        Self {
            capacity: 0,
            free: 0,
            pages: 0,
            full_pages: 0,
            free_pages: 0,
            page: SlabPage::new(),
        }
    }

    /// Initialize the [`SlabCommon`] with default values
    fn init(&mut self) -> Result<(), AllocError> {
        self.page.init()?;
        self.capacity = self.page.get_capacity() as u32;
        self.free = self.capacity;
        self.pages = 1;
        self.full_pages = 0;
        self.free_pages = 1;
        Ok(())
    }

    /// Add other [`SlabPage`].
    fn add_slab_page(&mut self, new_page: &mut SlabPage<N>) {
        let old_next_page = self.page.get_next_page();
        new_page.set_next_page(old_next_page);

        self.page
            .set_next_page(VirtAddr::from(new_page as *mut SlabPage<N>));

        let capacity = new_page.get_capacity() as u32;
        self.pages += 1;
        self.free_pages += 1;
        self.capacity += capacity;
        self.free += capacity;
    }

    /// Allocate other slot, caller must make sure there's at least one
    /// free slot
    fn allocate_slot(&mut self) -> VirtAddr {
        // Caller must make sure there's at least one free slot.
        assert_ne!(self.free, 0);
        let mut page = &mut self.page;
        loop {
            let free = page.get_free();

            if let Ok(vaddr) = page.allocate() {
                let capacity = page.get_capacity();
                self.free -= 1;

                if free == capacity {
                    self.free_pages -= 1;
                } else if free == 1 {
                    self.full_pages += 1;
                }

                return vaddr;
            }

            let next_page = page.get_next_page();
            // Cannot fail with free slots on entry.
            page = unsafe { next_page.aligned_mut().expect("Invalid next page") };
        }
    }

    /// Deallocate a slot given its virtual address
    fn deallocate_slot(&mut self, vaddr: VirtAddr) {
        let mut page = &mut self.page;
        loop {
            let free = page.get_free();

            if let Ok(_o) = page.free(vaddr) {
                let capacity = page.get_capacity();
                self.free += 1;

                if free == 0 {
                    self.full_pages -= 1;
                } else if free + 1 == capacity {
                    self.free_pages += 1;
                }

                return;
            }

            let next_page = page.get_next_page();
            // Will fail if the object does not belong to this slab.
            page = unsafe { next_page.aligned_mut().expect("Invalid next page") };
        }
    }

    /// Finds an unused slab page and removes it from the slab.
    fn free_one_page(&mut self) -> *mut SlabPage<N> {
        let mut last_page = &mut self.page;
        let mut next_page_vaddr = last_page.get_next_page();
        loop {
            let slab_page = unsafe {
                next_page_vaddr
                    .aligned_mut::<SlabPage<N>>()
                    .expect("couldn't find page to free")
            };
            next_page_vaddr = slab_page.get_next_page();

            let capacity = slab_page.get_capacity();
            let free = slab_page.get_free();
            if free != capacity {
                last_page = slab_page;
                continue;
            }

            let capacity = slab_page.get_capacity() as u32;
            self.pages -= 1;
            self.free_pages -= 1;
            self.capacity -= capacity;
            self.free -= capacity;

            last_page.set_next_page(slab_page.get_next_page());

            slab_page.destroy();

            return slab_page;
        }
    }
}

// 32 is chosen arbitrarily here, it does not affect struct layout
const SLAB_PAGE_SIZE: u16 = size_of::<SlabPage<32>>() as u16;

/// Represents a slab page for the [`SlabPageSlab`] allocator.
#[derive(Debug)]
struct SlabPageSlab {
    common: SlabCommon<SLAB_PAGE_SIZE>,
}

impl SlabPageSlab {
    /// Creates a new [`SlabPageSlab`] with a default [`SlabCommon`].
    const fn new() -> Self {
        Self {
            common: SlabCommon::new(),
        }
    }

    /// Initializes the [`SlabPageSlab`], allocating the first slab page if necessary.
    fn init(&mut self) -> Result<(), AllocError> {
        self.common.init()
    }

    /// Grows the slab by allocating a new slab page.
    fn grow_slab(&mut self) -> Result<(), AllocError> {
        if self.common.capacity == 0 {
            self.init()?;
            return Ok(());
        }

        // Make sure there's always at least one SlabPage slot left for extending the SlabPageSlab itself.
        if self.common.free >= 2 {
            return Ok(());
        }
        assert_ne!(self.common.free, 0);

        let page_vaddr = self.common.allocate_slot();
        let slab_page = unsafe { &mut *page_vaddr.as_mut_ptr::<SlabPage<SLAB_PAGE_SIZE>>() };

        *slab_page = SlabPage::new();
        if let Err(e) = slab_page.init() {
            self.common.deallocate_slot(page_vaddr);
            return Err(e);
        }

        self.common.add_slab_page(slab_page);

        Ok(())
    }

    /// Shrinks the slab by freeing unused slab pages.
    fn shrink_slab(&mut self) {
        // The SlabPageSlab uses SlabPages on its own and freeing a SlabPage can empty another SlabPage.
        while self.common.free_pages > 1 {
            let slab_page = self.common.free_one_page();
            self.common.deallocate_slot(VirtAddr::from(slab_page));
        }
    }

    /// Allocates a slot in the slab.
    ///
    /// # Returns
    ///
    /// Result containing a pointer to the allocated [`SlabPage`] or an `AllocError`.
    fn allocate(&mut self) -> Result<*mut SlabPage<SLAB_PAGE_SIZE>, AllocError> {
        self.grow_slab()?;
        Ok(self.common.allocate_slot().as_mut_ptr())
    }

    /// Deallocates a slab page, freeing the associated memory.
    ///
    /// # Arguments
    ///
    /// * `slab_page` - Pointer to the [`SlabPage`] to deallocate.
    fn deallocate(&mut self, slab_page: *mut SlabPage<SLAB_PAGE_SIZE>) {
        self.common.deallocate_slot(VirtAddr::from(slab_page));
        self.shrink_slab();
    }
}

/// Represents a slab allocator for fixed-size objects.
#[derive(Debug, Default)]
struct Slab<const N: u16> {
    common: SlabCommon<N>,
}

impl<const N: u16> Slab<N> {
    const fn new() -> Self {
        Self {
            common: SlabCommon::new(),
        }
    }

    /// Initialize the [`Slab`] instance
    fn init(&mut self) -> Result<(), AllocError> {
        self.common.init()
    }

    fn grow_slab(&mut self) -> Result<(), AllocError> {
        if self.common.capacity == 0 {
            return self.init();
        }

        if self.common.free != 0 {
            return Ok(());
        }

        let slab_page_ptr = SLAB_PAGE_SLAB.lock().allocate()?;
        let page_ptr = slab_page_ptr.cast::<SlabPage<N>>();
        unsafe { page_ptr.write(SlabPage::<N>::new()) };
        let page = unsafe { &mut *page_ptr };
        if let Err(e) = page.init() {
            SLAB_PAGE_SLAB.lock().deallocate(slab_page_ptr);
            return Err(e);
        }

        self.common.add_slab_page(page);
        Ok(())
    }

    fn shrink_slab(&mut self) {
        if self.common.free_pages <= 1 || 2 * self.common.free < self.common.capacity {
            return;
        }

        let slab_page = self.common.free_one_page();
        SLAB_PAGE_SLAB.lock().deallocate(slab_page.cast());
    }

    fn allocate(&mut self) -> Result<VirtAddr, AllocError> {
        self.grow_slab()?;
        Ok(self.common.allocate_slot())
    }

    fn deallocate(&mut self, vaddr: VirtAddr) {
        self.common.deallocate_slot(vaddr);
        self.shrink_slab();
    }
}

/// Static spinlock-protected instance of [`SlabPageSlab`] representing the
/// slab page allocator.
static SLAB_PAGE_SLAB: SpinLock<SlabPageSlab> = SpinLock::new(SlabPageSlab::new());

/// Represents a simple virtual-to-physical memory allocator ([`SvsmAllocator`])
/// implementing the [`GlobalAlloc`] trait.
///
/// This allocator uses slab allocation for fixed-size objects and falls
/// back to page allocation for larger objects.
#[derive(Debug, Default)]
pub struct SvsmAllocator {
    slab32: SpinLock<Slab<32>>,
    slab64: SpinLock<Slab<64>>,
    slab128: SpinLock<Slab<128>>,
    slab256: SpinLock<Slab<256>>,
    slab512: SpinLock<Slab<512>>,
    slab1024: SpinLock<Slab<1024>>,
    slab2048: SpinLock<Slab<2048>>,
}

impl SvsmAllocator {
    /// Creates a new instance of [`SvsmAllocator`] with initialized slab
    /// allocators.
    pub const fn new() -> Self {
        Self {
            slab32: SpinLock::new(Slab::new()),
            slab64: SpinLock::new(Slab::new()),
            slab128: SpinLock::new(Slab::new()),
            slab256: SpinLock::new(Slab::new()),
            slab512: SpinLock::new(Slab::new()),
            slab1024: SpinLock::new(Slab::new()),
            slab2048: SpinLock::new(Slab::new()),
        }
    }

    fn allocate(&self, size: usize) -> Option<Result<VirtAddr, AllocError>> {
        let size = size.checked_next_power_of_two()?;
        match size {
            ..=32 => Some(self.slab32.lock().allocate()),
            64 => Some(self.slab64.lock().allocate()),
            128 => Some(self.slab128.lock().allocate()),
            256 => Some(self.slab256.lock().allocate()),
            512 => Some(self.slab512.lock().allocate()),
            1024 => Some(self.slab1024.lock().allocate()),
            2048 => Some(self.slab2048.lock().allocate()),
            _ => None,
        }
    }

    fn deallocate(&self, addr: VirtAddr, size: usize) -> Option<()> {
        let size = size.checked_next_power_of_two()?;
        match size {
            ..=32 => self.slab32.lock().deallocate(addr),
            64 => self.slab64.lock().deallocate(addr),
            128 => self.slab128.lock().deallocate(addr),
            256 => self.slab256.lock().deallocate(addr),
            512 => self.slab512.lock().deallocate(addr),
            1024 => self.slab1024.lock().deallocate(addr),
            2048 => self.slab2048.lock().deallocate(addr),
            _ => return None,
        }

        Some(())
    }

    /// Resets the internal state. This is equivalent to reassigning `self`
    /// with a newly created [`SvsmAllocator`] with `Self::new()`.
    #[cfg(all(not(test_in_svsm), any(test, fuzzing)))]
    fn reset(&self) {
        *self.slab32.lock() = Slab::new();
        *self.slab64.lock() = Slab::new();
        *self.slab128.lock() = Slab::new();
        *self.slab256.lock() = Slab::new();
        *self.slab512.lock() = Slab::new();
        *self.slab1024.lock() = Slab::new();
        *self.slab2048.lock() = Slab::new();
    }
}

unsafe impl GlobalAlloc for SvsmAllocator {
    /// Allocates memory based on the specified layout.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let ret = match self.allocate(size) {
            Some(v) => v.map_err(Into::into),
            None => {
                let order = get_order(size);
                if order >= MAX_ORDER {
                    return ptr::null_mut();
                }
                allocate_pages(order)
            }
        };
        ret.map_or_else(|_| ptr::null_mut(), |addr| addr.as_mut_ptr::<u8>())
    }

    /// Deallocates memory based on the specified pointer and layout.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let virt_addr = VirtAddr::from(ptr);
        let size = layout.size();

        let info = {
            let mem = ROOT_MEM.lock();
            let pfn = mem.get_pfn(virt_addr).expect("Freeing unknown memory");
            mem.read_page_info(pfn)
        };

        match info {
            PageInfo::Allocated(_ai) => {
                free_page(virt_addr);
            }
            PageInfo::Slab(_) => {
                self.deallocate(virt_addr, size).expect("Invalid page info");
            }
            _ => {
                panic!("Freeing memory on unsupported page type");
            }
        }
    }
}

#[cfg_attr(any(target_os = "none"), global_allocator)]
#[allow(dead_code)]
static ALLOCATOR: SvsmAllocator = SvsmAllocator::new();

/// Initializes the root memory region with the specified physical start
/// address, virtual start address, and page count.
pub fn root_mem_init(pstart: PhysAddr, vstart: VirtAddr, page_count: usize) {
    {
        let mut region = ROOT_MEM.lock();
        region.start_phys = pstart;
        region.start_virt = vstart;
        region.page_count = page_count;
        region.init_memory();
        // drop lock here so slab initialization does not deadlock
    }

    SLAB_PAGE_SLAB
        .lock()
        .init()
        .expect("Failed to initialize SLAB_PAGE_SLAB");
}

#[cfg(any(test, fuzzing))]
/// A global lock on global memory. Should only be acquired via
/// [`TestRootMem::setup()`].
static TEST_ROOT_MEM_LOCK: SpinLock<()> = SpinLock::new(());

pub const MIN_ALIGN: usize = 32;

pub fn layout_from_size(size: usize) -> Result<Layout, AllocError> {
    let align: usize = {
        if (size % PAGE_SIZE) == 0 {
            PAGE_SIZE
        } else {
            MIN_ALIGN
        }
    };
    Layout::from_size_align(size, align).map_err(|_| AllocError::InvalidLayout)
}

pub fn layout_from_ptr(ptr: *mut u8) -> Option<Layout> {
    let va = VirtAddr::from(ptr);

    let root = ROOT_MEM.lock();
    let pfn = root.get_pfn(va).ok()?;
    let info = root.read_page_info(pfn);

    match info {
        PageInfo::Allocated(ai) => {
            let base: usize = 2;
            let size: usize = base.pow(ai.order as u32) * PAGE_SIZE;
            Some(Layout::from_size_align(size, PAGE_SIZE).unwrap())
        }
        PageInfo::Slab(si) => {
            let size = si.item_size as usize;
            Some(Layout::from_size_align(size, size).unwrap())
        }
        _ => None,
    }
}

#[cfg(test)]
pub const DEFAULT_TEST_MEMORY_SIZE: usize = 16usize * 1024 * 1024;

/// A dummy struct to acquire a lock over global memory for tests.
#[cfg(any(test, fuzzing))]
#[derive(Debug)]
#[expect(dead_code)]
pub struct TestRootMem<'a>(LockGuard<'a, ()>);

#[cfg(any(test, fuzzing))]
impl TestRootMem<'_> {
    #[cfg(test_in_svsm)]
    /// Sets up a test environment, returning a guard to ensure memory is
    /// held for the test's duration. This test function is intended to
    /// called inside a running SVSM.
    ///
    /// # Returns
    ///
    /// A guard that ensures the memory lock is held during the test.
    #[must_use = "memory guard must be held for the whole test"]
    pub fn setup(_size: usize) -> Self {
        // We do not need to set up root memory if running inside the SVSM.
        Self(TEST_ROOT_MEM_LOCK.lock())
    }

    /// Sets up a test environment, returning a guard to ensure memory is
    /// held for the test's duration. This function does not run inside
    /// the SVSM.
    ///
    /// # Returns
    ///
    /// A guard that ensures the memory lock is held during the test.
    #[cfg(not(test_in_svsm))]
    #[must_use = "memory guard must be held for the whole test"]
    pub fn setup(size: usize) -> Self {
        extern crate alloc;
        use alloc::alloc::{alloc, handle_alloc_error};

        let layout = Layout::from_size_align(size, PAGE_SIZE)
            .unwrap()
            .pad_to_align();
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        } else if ptr as usize & (PAGE_SIZE - 1) != 0 {
            panic!("test memory region allocation not aligned to page size");
        }

        let page_count = layout.size() / PAGE_SIZE;
        let guard = Self(TEST_ROOT_MEM_LOCK.lock());
        let vaddr = VirtAddr::from(ptr);
        let paddr = PhysAddr::from(vaddr.bits()); // Identity mapping
        root_mem_init(paddr, vaddr, page_count);
        guard
    }
}

#[cfg(all(not(test_in_svsm), any(test, fuzzing)))]
impl Drop for TestRootMem<'_> {
    /// If running tests in userspace, destroy root memory before
    /// dropping the lock over it.
    fn drop(&mut self) {
        extern crate alloc;
        use alloc::alloc::dealloc;

        let mut root_mem = ROOT_MEM.lock();
        let layout = Layout::from_size_align(root_mem.page_count * PAGE_SIZE, PAGE_SIZE).unwrap();
        unsafe { dealloc(root_mem.start_virt.as_mut_ptr::<u8>(), layout) };
        *root_mem = MemoryRegion::new();

        // Reset the Slabs
        *SLAB_PAGE_SLAB.lock() = SlabPageSlab::new();
        ALLOCATOR.reset();
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;
    use super::*;
    use crate::mm::PageBox;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Tests the setup of the root memory
    #[test]
    fn test_root_mem_setup() {
        let test_mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        drop(test_mem_lock);
    }

    /// Tests the allocation and deallocation of a single page, verifying the
    /// memory information.
    #[test]
    fn test_page_alloc_one() {
        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut root_mem = ROOT_MEM.lock();

        let info_before = root_mem.memory_info();
        let page = root_mem.allocate_page().unwrap();
        assert!(!page.is_null());
        assert_ne!(info_before.free_pages, root_mem.memory_info().free_pages);
        root_mem.free_page(page);
        assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    /// Allocate and free all available compound pages, verify that memory_info()
    /// reflects it.
    fn test_page_alloc_all_compound() {
        extern crate alloc;
        use alloc::vec::Vec;

        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut root_mem = ROOT_MEM.lock();

        let info_before = root_mem.memory_info();
        let mut allocs: [Vec<VirtAddr>; MAX_ORDER] = Default::default();
        for (o, alloc) in allocs.iter_mut().enumerate().take(MAX_ORDER) {
            for _i in 0..info_before.free_pages[o] {
                let pages = root_mem.allocate_pages(o).unwrap();
                assert!(!pages.is_null());
                alloc.push(pages);
            }
        }
        let info_after = root_mem.memory_info();
        for o in 0..MAX_ORDER {
            assert_eq!(info_after.free_pages[o], 0);
        }

        for alloc in allocs.iter().take(MAX_ORDER) {
            for pages in &alloc[..] {
                root_mem.free_page(*pages);
            }
        }
        assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    /// Allocate and free all available 4k pages, verify that memory_info()
    /// reflects it.
    fn test_page_alloc_all_single() {
        extern crate alloc;
        use alloc::vec::Vec;

        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut root_mem = ROOT_MEM.lock();

        let info_before = root_mem.memory_info();
        let mut allocs: Vec<VirtAddr> = Vec::new();
        for o in 0..MAX_ORDER {
            for _i in 0..info_before.free_pages[o] {
                for _j in 0..(1usize << o) {
                    let page = root_mem.allocate_page().unwrap();
                    assert!(!page.is_null());
                    allocs.push(page);
                }
            }
        }
        let info_after = root_mem.memory_info();
        for o in 0..MAX_ORDER {
            assert_eq!(info_after.free_pages[o], 0);
        }

        for page in &allocs[..] {
            root_mem.free_page(*page);
        }
        assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    /// Allocate and free all available compound pages, verify that any subsequent
    /// allocation fails.
    fn test_page_alloc_oom() {
        extern crate alloc;
        use alloc::vec::Vec;

        let _test_mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut root_mem = ROOT_MEM.lock();

        let info_before = root_mem.memory_info();
        let mut allocs: [Vec<VirtAddr>; MAX_ORDER] = Default::default();
        for (o, alloc) in allocs.iter_mut().enumerate().take(MAX_ORDER) {
            for _i in 0..info_before.free_pages[o] {
                let pages = root_mem.allocate_pages(o).unwrap();
                assert!(!pages.is_null());
                alloc.push(pages);
            }
        }
        let info_after = root_mem.memory_info();
        for o in 0..MAX_ORDER {
            assert_eq!(info_after.free_pages[o], 0);
        }

        let page = root_mem.allocate_page();
        if page.is_ok() {
            panic!("unexpected page allocation success after memory exhaustion");
        }

        for alloc in allocs.iter().take(MAX_ORDER) {
            for pages in &alloc[..] {
                root_mem.free_page(*pages);
            }
        }
        assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);
    }

    #[test]
    fn test_page_file() {
        let _mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut root_mem = ROOT_MEM.lock();

        // Allocate page and check ref-count
        let vaddr = root_mem.allocate_file_page().unwrap();
        let pfn = root_mem.get_pfn(vaddr).unwrap();
        let info = root_mem.read_page_info(pfn);

        assert!(matches!(info, PageInfo::File(ref fi) if fi.ref_count == 1));

        // Get another reference and check ref-count
        root_mem.get_file_page(vaddr).expect("Not a file page");
        let info = root_mem.read_page_info(pfn);

        assert!(matches!(info, PageInfo::File(ref fi) if fi.ref_count == 2));

        // Drop reference and check ref-count
        root_mem.put_file_page(vaddr).expect("Not a file page");
        let info = root_mem.read_page_info(pfn);

        assert!(matches!(info, PageInfo::File(ref fi) if fi.ref_count == 1));

        // Drop last reference and check if page is released
        root_mem.put_file_page(vaddr).expect("Not a file page");
        let info = root_mem.read_page_info(pfn);

        assert!(matches!(info, PageInfo::Free { .. }));
    }

    const TEST_SLAB_SIZES: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];

    #[test]
    /// Allocate and free a couple of objects for each slab size.
    fn test_slab_alloc_free_many() {
        extern crate alloc;
        use alloc::vec::Vec;

        let _mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

        // Run it twice to make sure some objects will get freed and allocated again.
        for _i in 0..2 {
            let mut allocs: [Vec<*mut u8>; TEST_SLAB_SIZES.len()] = Default::default();
            let mut j = 0;
            for size in TEST_SLAB_SIZES {
                let layout = Layout::from_size_align(size, size).unwrap().pad_to_align();
                assert_eq!(layout.size(), size);

                // Allocate four pages worth of objects from each Slab.
                let n = (4 * PAGE_SIZE).div_ceil(size);
                for _k in 0..n {
                    let p = unsafe { ALLOCATOR.alloc(layout) };
                    assert_ne!(p, ptr::null_mut());
                    allocs[j].push(p);
                }
                j += 1;
            }

            j = 0;
            for size in TEST_SLAB_SIZES {
                let layout = Layout::from_size_align(size, size).unwrap().pad_to_align();
                assert_eq!(layout.size(), size);

                for p in &allocs[j][..] {
                    unsafe { ALLOCATOR.dealloc(*p, layout) };
                }
                j += 1;
            }
        }
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    /// Allocate enough objects so that the SlabPageSlab will need a SlabPage for
    /// itself twice.
    fn test_slab_page_slab_for_self() {
        extern crate alloc;
        use alloc::vec::Vec;

        let _mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

        const OBJECT_SIZE: usize = TEST_SLAB_SIZES[0];
        const OBJECTS_PER_PAGE: usize = PAGE_SIZE / OBJECT_SIZE;

        const SLAB_PAGES_PER_PAGE: usize = PAGE_SIZE / SLAB_PAGE_SIZE as usize;

        let layout = Layout::from_size_align(OBJECT_SIZE, OBJECT_SIZE)
            .unwrap()
            .pad_to_align();
        assert_eq!(layout.size(), OBJECT_SIZE);

        let mut allocs: Vec<*mut u8> = Vec::new();
        for _i in 0..(2 * SLAB_PAGES_PER_PAGE * OBJECTS_PER_PAGE) {
            let p = unsafe { ALLOCATOR.alloc(layout) };
            assert_ne!(p, ptr::null_mut());
            assert_ne!(SLAB_PAGE_SLAB.lock().common.capacity, 0);
            allocs.push(p);
        }

        for p in allocs {
            unsafe { ALLOCATOR.dealloc(p, layout) };
        }

        assert_ne!(SLAB_PAGE_SLAB.lock().common.free, 0);
        assert!(SLAB_PAGE_SLAB.lock().common.free_pages < 2);
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "FIXME")]
    /// Allocate enough objects to hit an OOM situation and verify null gets
    /// returned at some point.
    fn test_slab_oom() {
        extern crate alloc;
        use alloc::vec::Vec;

        const TEST_MEMORY_SIZE: usize = 256 * PAGE_SIZE;
        let _mem_lock = TestRootMem::setup(TEST_MEMORY_SIZE);

        const OBJECT_SIZE: usize = TEST_SLAB_SIZES[0];
        let layout = Layout::from_size_align(OBJECT_SIZE, OBJECT_SIZE)
            .unwrap()
            .pad_to_align();
        assert_eq!(layout.size(), OBJECT_SIZE);

        let mut allocs: Vec<*mut u8> = Vec::new();
        let mut null_seen = false;
        for _i in 0..TEST_MEMORY_SIZE.div_ceil(OBJECT_SIZE) {
            let p = unsafe { ALLOCATOR.alloc(layout) };
            if p.is_null() {
                null_seen = true;
                break;
            }
            allocs.push(p);
        }

        if !null_seen {
            panic!("unexpected slab allocation success after memory exhaustion");
        }

        for p in allocs {
            unsafe { ALLOCATOR.dealloc(p, layout) };
        }
    }

    /// Helper to assert that a `PageBox` is properly dropped.
    fn check_drop_page<T: ?Sized>(page: PageBox<T>) {
        let vaddr = page.vaddr();
        {
            let mem = ROOT_MEM.lock();
            let pfn = mem.get_pfn(vaddr).unwrap();
            let info = mem.read_page_info(pfn);
            assert!(matches!(info, PageInfo::Allocated(..)));
        }
        drop(page);
        {
            let mem = ROOT_MEM.lock();
            let pfn = mem.get_pfn(vaddr).unwrap();
            let info = mem.read_page_info(pfn);
            assert!(matches!(info, PageInfo::Free { .. }));
        }
    }

    #[test]
    fn test_drop_pagebox() {
        // Check that the inner contents of the [`PageBox`] are only dropped
        // once.
        static DROPPED: AtomicUsize = AtomicUsize::new(0);

        struct Thing(Box<u32>);

        impl Drop for Thing {
            fn drop(&mut self) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }

        let _mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

        let page = PageBox::try_new(Thing(Box::new(44))).unwrap();
        assert_eq!(*page.0, 44);

        check_drop_page(page);
        assert_eq!(DROPPED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_drop_pagebox_slice() {
        use core::num::NonZeroUsize;

        const NUM_ITEMS: NonZeroUsize = NonZeroUsize::new(8192).unwrap();
        static DROPPED: AtomicUsize = AtomicUsize::new(0);

        #[derive(Clone)]
        struct Thing(Box<u32>);

        impl Drop for Thing {
            fn drop(&mut self) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }

        let _mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

        let slice = PageBox::try_new_slice(Thing(Box::new(43)), NUM_ITEMS).unwrap();

        // Check that contents match
        for item in slice.iter() {
            assert_eq!(*item.0, 43);
        }
        assert_eq!(slice.len(), NUM_ITEMS.get());

        check_drop_page(slice);
        // All the items in the slice must have dropped, plus the original
        // value that items were cloned out of.
        assert_eq!(DROPPED.load(Ordering::Relaxed), NUM_ITEMS.get() + 1);
    }
}
