// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
#[cfg(any(test, fuzzing))]
use crate::locking::LockGuard;
use crate::locking::SpinLock;
use crate::mm::virt_to_phys;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::utils::{align_down, align_up, zero_mem_region};
use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::ptr;
use log;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    InvalidPageType,
    InvalidHeapAddress(VirtAddr),
    OutOfMemory,
    InvalidPageOrder(usize),
    InvalidFilePage(VirtAddr),
    InvalidPfn(usize),
}

impl From<AllocError> for SvsmError {
    fn from(err: AllocError) -> Self {
        Self::Alloc(err)
    }
}

// Support allocations up to order-5 (128kb)
pub const MAX_ORDER: usize = 6;

pub fn get_order(size: usize) -> usize {
    (size
        .checked_next_power_of_two()
        .map_or(usize::BITS, usize::ilog2) as usize)
        .saturating_sub(PAGE_SHIFT)
}

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

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct PageStorageType(u64);

impl PageStorageType {
    const TYPE_SHIFT: u64 = 4;
    const TYPE_MASK: u64 = (1u64 << Self::TYPE_SHIFT) - 1;
    const NEXT_SHIFT: u64 = 12;
    const NEXT_MASK: u64 = !((1u64 << Self::NEXT_SHIFT) - 1);
    const ORDER_MASK: u64 = (1u64 << (Self::NEXT_SHIFT - Self::TYPE_SHIFT)) - 1;

    const fn new(t: PageType) -> Self {
        Self(t as u64)
    }

    fn encode_order(self, order: usize) -> Self {
        Self(self.0 | ((order as u64) & Self::ORDER_MASK) << Self::TYPE_SHIFT)
    }

    fn encode_next(self, next_page: usize) -> Self {
        Self(self.0 | (next_page as u64) << Self::NEXT_SHIFT)
    }

    fn encode_refcount(self, refcount: u64) -> Self {
        Self(self.0 | refcount << Self::TYPE_SHIFT)
    }

    fn decode_order(&self) -> usize {
        ((self.0 >> Self::TYPE_SHIFT) & Self::ORDER_MASK) as usize
    }

    fn decode_next(&self) -> usize {
        ((self.0 & Self::NEXT_MASK) >> Self::NEXT_SHIFT) as usize
    }

    fn decode_refcount(&self) -> u64 {
        self.0 >> Self::TYPE_SHIFT
    }

    fn page_type(&self) -> Result<PageType, AllocError> {
        PageType::try_from(self.0 & Self::TYPE_MASK)
    }
}

#[derive(Clone, Copy, Debug)]
struct FreeInfo {
    next_page: usize,
    order: usize,
}

impl FreeInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Free)
            .encode_order(self.order)
            .encode_next(self.next_page)
    }

    fn decode(mem: PageStorageType) -> Self {
        let next_page = mem.decode_next();
        let order = mem.decode_order();
        Self { next_page, order }
    }
}

#[derive(Clone, Copy, Debug)]
struct AllocatedInfo {
    order: usize,
}

impl AllocatedInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Allocated).encode_order(self.order)
    }

    fn decode(mem: PageStorageType) -> Self {
        let order = mem.decode_order();
        Self { order }
    }
}

#[derive(Clone, Copy, Debug)]
struct SlabPageInfo;

impl SlabPageInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::SlabPage)
    }

    fn decode(_mem: PageStorageType) -> Self {
        Self
    }
}

#[derive(Clone, Copy, Debug)]
struct CompoundInfo {
    order: usize,
}

impl CompoundInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Compound).encode_order(self.order)
    }

    fn decode(mem: PageStorageType) -> Self {
        let order = mem.decode_order();
        Self { order }
    }
}

#[derive(Clone, Copy, Debug)]
struct ReservedInfo;

impl ReservedInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::Reserved)
    }

    fn decode(_mem: PageStorageType) -> Self {
        Self
    }
}

#[derive(Clone, Copy, Debug)]
struct FileInfo {
    /// Reference count
    ref_count: u64,
}

impl FileInfo {
    const fn new(ref_count: u64) -> Self {
        Self { ref_count }
    }

    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PageType::File).encode_refcount(self.ref_count)
    }

    fn decode(mem: PageStorageType) -> Self {
        let ref_count = mem.decode_refcount();
        Self { ref_count }
    }
}

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

#[derive(Debug, Default, Clone, Copy)]
pub struct MemInfo {
    total_pages: [usize; MAX_ORDER],
    free_pages: [usize; MAX_ORDER],
}

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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    fn virt_to_phys(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let offset = self.get_virt_offset(vaddr)?;
        Some(self.start_phys + offset)
    }

    /// # Safety
    ///
    /// The caller must provide a valid pfn, otherwise the returned pointer is
    /// undefined, as the compiler is allowed to optimize assuming there will
    /// be no arithmetic overflows.
    unsafe fn page_info_ptr(&self, pfn: usize) -> *mut PageStorageType {
        self.start_virt.as_mut_ptr::<PageStorageType>().add(pfn)
    }

    fn check_pfn(&self, pfn: usize) {
        if pfn >= self.page_count {
            panic!("Invalid Page Number {}", pfn);
        }
    }

    fn end_virt(&self) -> VirtAddr {
        self.start_virt + (self.page_count * PAGE_SIZE)
    }

    fn write_page_info(&self, pfn: usize, pi: PageInfo) {
        self.check_pfn(pfn);

        let info: PageStorageType = pi.to_mem();
        unsafe { self.page_info_ptr(pfn).write(info) };
    }

    fn read_page_info(&self, pfn: usize) -> PageInfo {
        self.check_pfn(pfn);

        let info = unsafe { self.page_info_ptr(pfn).read() };
        PageInfo::from_mem(info)
    }

    fn get_virt_offset(&self, vaddr: VirtAddr) -> Option<usize> {
        (self.start_virt <= vaddr && vaddr < self.end_virt()).then(|| vaddr - self.start_virt)
    }

    fn get_pfn(&self, vaddr: VirtAddr) -> Result<usize, AllocError> {
        self.get_virt_offset(vaddr)
            .map(|off| off / PAGE_SIZE)
            .ok_or(AllocError::InvalidHeapAddress(vaddr))
    }

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

    fn mark_compound_page(&mut self, pfn: usize, order: usize) {
        let nr_pages: usize = 1 << order;
        let compound = PageInfo::Compound(CompoundInfo { order });
        for i in 1..nr_pages {
            self.write_page_info(pfn + i, compound);
        }
    }

    fn init_compound_page(&mut self, pfn: usize, order: usize, next_pfn: usize) {
        let head = PageInfo::Free(FreeInfo {
            next_page: next_pfn,
            order,
        });
        self.write_page_info(pfn, head);
        self.mark_compound_page(pfn, order);
    }

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

    fn allocate_pages_info(&mut self, order: usize, pg: PageInfo) -> Result<VirtAddr, AllocError> {
        self.refill_page_list(order)?;
        let pfn = self.get_next_page(order)?;
        self.write_page_info(pfn, pg);
        Ok(self.start_virt + (pfn * PAGE_SIZE))
    }

    fn allocate_pages(&mut self, order: usize) -> Result<VirtAddr, AllocError> {
        let pg = PageInfo::Allocated(AllocatedInfo { order });
        self.allocate_pages_info(order, pg)
    }

    fn allocate_page(&mut self) -> Result<VirtAddr, AllocError> {
        self.allocate_pages(0)
    }

    fn allocate_zeroed_page(&mut self) -> Result<VirtAddr, AllocError> {
        let vaddr = self.allocate_page()?;

        zero_mem_region(vaddr, vaddr + PAGE_SIZE);

        Ok(vaddr)
    }

    fn allocate_slab_page(&mut self) -> Result<VirtAddr, AllocError> {
        let pg = PageInfo::Slab(SlabPageInfo);
        self.allocate_pages_info(0, pg)
    }

    fn allocate_file_page(&mut self) -> Result<VirtAddr, AllocError> {
        let pg = PageInfo::File(FileInfo::new(1));
        self.allocate_pages_info(0, pg)
    }

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

    fn next_free_pfn(&self, pfn: usize, order: usize) -> usize {
        let page = self.read_page_info(pfn);
        let PageInfo::Free(fi) = page else {
            panic!("Unexpected page type in free-list for order {}", order);
        };

        fi.next_page
    }

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

    fn memory_info(&self) -> MemInfo {
        MemInfo {
            total_pages: self.nr_pages,
            free_pages: self.free_pages,
        }
    }

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

#[derive(Debug)]
pub struct PageRef {
    virt_addr: VirtAddr,
    phys_addr: PhysAddr,
}

impl PageRef {
    pub const fn new(virt_addr: VirtAddr, phys_addr: PhysAddr) -> Self {
        Self {
            virt_addr,
            phys_addr,
        }
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.virt_addr
    }

    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }
}

impl AsRef<[u8; PAGE_SIZE]> for PageRef {
    fn as_ref(&self) -> &[u8; PAGE_SIZE] {
        let ptr = self.virt_addr.as_ptr::<[u8; PAGE_SIZE]>();
        unsafe { ptr.as_ref().unwrap() }
    }
}

impl AsMut<[u8; PAGE_SIZE]> for PageRef {
    fn as_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
        let ptr = self.virt_addr.as_mut_ptr::<[u8; PAGE_SIZE]>();
        unsafe { ptr.as_mut().unwrap() }
    }
}

impl Clone for PageRef {
    fn clone(&self) -> Self {
        get_file_page(self.virt_addr).expect("Failed to get page reference");
        PageRef {
            virt_addr: self.virt_addr,
            phys_addr: self.phys_addr,
        }
    }
}

impl Drop for PageRef {
    fn drop(&mut self) {
        put_file_page(self.virt_addr).expect("Failed to drop page reference");
    }
}

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

static ROOT_MEM: SpinLock<MemoryRegion> = SpinLock::new(MemoryRegion::new());

pub fn allocate_page() -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_page()?)
}

pub fn allocate_pages(order: usize) -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_pages(order)?)
}

pub fn allocate_slab_page() -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_slab_page()?)
}

pub fn allocate_zeroed_page() -> Result<VirtAddr, SvsmError> {
    Ok(ROOT_MEM.lock().allocate_zeroed_page()?)
}

pub fn allocate_file_page() -> Result<VirtAddr, SvsmError> {
    let vaddr = ROOT_MEM.lock().allocate_file_page()?;
    zero_mem_region(vaddr, vaddr + PAGE_SIZE);
    Ok(vaddr)
}

pub fn allocate_file_page_ref() -> Result<PageRef, SvsmError> {
    let v = allocate_file_page()?;
    let p = virt_to_phys(v);

    Ok(PageRef::new(v, p))
}

fn get_file_page(vaddr: VirtAddr) -> Result<(), SvsmError> {
    Ok(ROOT_MEM.lock().get_file_page(vaddr)?)
}

fn put_file_page(vaddr: VirtAddr) -> Result<(), SvsmError> {
    Ok(ROOT_MEM.lock().put_file_page(vaddr)?)
}

pub fn free_page(vaddr: VirtAddr) {
    ROOT_MEM.lock().free_page(vaddr)
}

pub fn memory_info() -> MemInfo {
    ROOT_MEM.lock().memory_info()
}

#[derive(Debug, Default)]
struct SlabPage {
    vaddr: VirtAddr,
    capacity: u16,
    free: u16,
    item_size: u16,
    used_bitmap: [u64; 2],
    next_page: VirtAddr,
}

impl SlabPage {
    const fn new() -> Self {
        Self {
            vaddr: VirtAddr::null(),
            capacity: 0,
            free: 0,
            item_size: 0,
            used_bitmap: [0; 2],
            next_page: VirtAddr::null(),
        }
    }

    fn init(&mut self, mut item_size: u16) -> Result<(), AllocError> {
        if self.item_size != 0 {
            return Ok(());
        }

        assert!(item_size <= (PAGE_SIZE / 2) as u16);
        assert!(self.vaddr.is_null());

        if item_size < 32 {
            item_size = 32;
        }

        let vaddr = ROOT_MEM.lock().allocate_slab_page()?;
        self.vaddr = vaddr;
        self.item_size = item_size;
        self.capacity = (PAGE_SIZE as u16) / item_size;
        self.free = self.capacity;

        Ok(())
    }

    fn destroy(&mut self) {
        if self.vaddr.is_null() {
            return;
        }

        free_page(self.vaddr);
    }

    fn get_capacity(&self) -> u16 {
        self.capacity
    }

    fn get_free(&self) -> u16 {
        self.free
    }

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

        for i in 0..self.capacity {
            let idx = (i / 64) as usize;
            let mask = 1u64 << (i % 64);

            if self.used_bitmap[idx] & mask == 0 {
                self.used_bitmap[idx] |= mask;
                self.free -= 1;
                return Ok(self.vaddr + ((self.item_size * i) as usize));
            }
        }

        Err(AllocError::OutOfMemory)
    }

    fn free(&mut self, vaddr: VirtAddr) -> Result<(), AllocError> {
        if vaddr < self.vaddr || vaddr >= self.vaddr + PAGE_SIZE {
            return Err(AllocError::InvalidHeapAddress(vaddr));
        }

        assert!(self.item_size > 0);

        let item_size = self.item_size as usize;
        let offset = vaddr - self.vaddr;
        let i = offset / item_size;
        let idx = i / 64;
        let mask = 1u64 << (i % 64);

        self.used_bitmap[idx] &= !mask;
        self.free += 1;

        Ok(())
    }
}

#[derive(Debug, Default)]
#[repr(align(16))]
struct SlabCommon {
    item_size: u16,
    capacity: u32,
    free: u32,
    pages: u32,
    full_pages: u32,
    free_pages: u32,
    page: SlabPage,
}

impl SlabCommon {
    const fn new(item_size: u16) -> Self {
        Self {
            item_size,
            capacity: 0,
            free: 0,
            pages: 0,
            full_pages: 0,
            free_pages: 0,
            page: SlabPage::new(),
        }
    }

    fn init(&mut self) -> Result<(), AllocError> {
        self.page.init(self.item_size)?;

        self.capacity = self.page.get_capacity() as u32;
        self.free = self.capacity;
        self.pages = 1;
        self.full_pages = 0;
        self.free_pages = 1;

        Ok(())
    }

    fn add_slab_page(&mut self, new_page: &mut SlabPage) {
        let old_next_page = self.page.get_next_page();
        new_page.set_next_page(old_next_page);
        self.page
            .set_next_page(VirtAddr::from(new_page as *mut SlabPage));

        let capacity = new_page.get_capacity() as u32;
        self.pages += 1;
        self.free_pages += 1;
        self.capacity += capacity;
        self.free += capacity;
    }

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
            assert!(!next_page.is_null()); // Cannot happen with free slots on entry.
            page = unsafe { &mut *next_page.as_mut_ptr::<SlabPage>() };
        }
    }

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
            assert!(!next_page.is_null()); // Object does not belong to this Slab.
            page = unsafe { &mut *next_page.as_mut_ptr::<SlabPage>() };
        }
    }

    /// Finds an unused slab page and removes it from the slab.
    fn free_one_page(&mut self) -> *mut SlabPage {
        let mut last_page = &mut self.page;
        let mut next_page_vaddr = last_page.get_next_page();
        loop {
            if next_page_vaddr.is_null() {
                unreachable!("couldn't find page to free");
            }
            let slab_page = unsafe { &mut *next_page_vaddr.as_mut_ptr::<SlabPage>() };
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

#[derive(Debug)]
struct SlabPageSlab {
    common: SlabCommon,
}

impl SlabPageSlab {
    const fn new() -> Self {
        Self {
            common: SlabCommon::new(size_of::<SlabPage>() as u16),
        }
    }

    fn init(&mut self) -> Result<(), AllocError> {
        self.common.init()
    }

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
        let slab_page = unsafe { &mut *page_vaddr.as_mut_ptr::<SlabPage>() };

        *slab_page = SlabPage::new();
        if let Err(e) = slab_page.init(self.common.item_size) {
            self.common.deallocate_slot(page_vaddr);
            return Err(e);
        }

        self.common.add_slab_page(slab_page);

        Ok(())
    }

    fn shrink_slab(&mut self) {
        // The SlabPageSlab uses SlabPages on its own and freeing a SlabPage can empty another SlabPage.
        while self.common.free_pages > 1 {
            let slab_page = self.common.free_one_page();
            self.common.deallocate_slot(VirtAddr::from(slab_page));
        }
    }

    fn allocate(&mut self) -> Result<*mut SlabPage, AllocError> {
        self.grow_slab()?;
        Ok(self.common.allocate_slot().as_mut_ptr::<SlabPage>())
    }

    fn deallocate(&mut self, slab_page: *mut SlabPage) {
        self.common.deallocate_slot(VirtAddr::from(slab_page));
        self.shrink_slab();
    }
}

#[derive(Debug, Default)]
struct Slab {
    common: SlabCommon,
}

impl Slab {
    const fn new(item_size: u16) -> Self {
        Self {
            common: SlabCommon::new(item_size),
        }
    }

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

        let slab_page = SLAB_PAGE_SLAB
            .lock()
            .allocate()
            .map(|ptr| unsafe { &mut *ptr })?;
        *slab_page = SlabPage::new();
        if let Err(e) = slab_page.init(self.common.item_size) {
            SLAB_PAGE_SLAB.lock().deallocate(slab_page);
            return Err(e);
        }

        self.common.add_slab_page(slab_page);
        Ok(())
    }

    fn shrink_slab(&mut self) {
        if self.common.free_pages <= 1 || 2 * self.common.free < self.common.capacity {
            return;
        }

        let slab_page = self.common.free_one_page();
        SLAB_PAGE_SLAB.lock().deallocate(slab_page);
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

static SLAB_PAGE_SLAB: SpinLock<SlabPageSlab> = SpinLock::new(SlabPageSlab::new());

#[derive(Debug)]
pub struct SvsmAllocator {
    slabs: [SpinLock<Slab>; 7],
}

impl SvsmAllocator {
    const MIN_SLAB_SIZE: u16 = 32;
    const MIN_ALIGNMENT: u32 = Self::MIN_SLAB_SIZE.trailing_zeros();

    pub const fn new() -> Self {
        Self {
            slabs: [
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE)),
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE * 2)),
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE * 4)),
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE * 8)),
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE * 16)),
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE * 32)),
                SpinLock::new(Slab::new(Self::MIN_SLAB_SIZE * 64)),
            ],
        }
    }

    /// Get a reference to the appropriate slab for an allocation of the specified size,
    /// or [`None`] if the size is too big.
    fn get_slab(&self, size: usize) -> Option<&SpinLock<Slab>> {
        let slab_size = size.checked_next_power_of_two()?;
        // Go from an allocation size to an index into `self.slabs`.
        let idx = slab_size
            .trailing_zeros()
            .saturating_sub(Self::MIN_ALIGNMENT) as usize;
        // The index might be too large, so use a safe getter.
        self.slabs.get(idx)
    }

    /// Resets the internal state. This is equivalent to reassigning `self`
    /// with `Self::new()`.
    #[cfg(all(not(test_in_svsm), any(test, fuzzing)))]
    fn reset(&self) {
        *self.slabs[0].lock() = Slab::new(Self::MIN_SLAB_SIZE);
        *self.slabs[1].lock() = Slab::new(Self::MIN_SLAB_SIZE * 2);
        *self.slabs[2].lock() = Slab::new(Self::MIN_SLAB_SIZE * 4);
        *self.slabs[3].lock() = Slab::new(Self::MIN_SLAB_SIZE * 8);
        *self.slabs[4].lock() = Slab::new(Self::MIN_SLAB_SIZE * 16);
        *self.slabs[5].lock() = Slab::new(Self::MIN_SLAB_SIZE * 32);
        *self.slabs[6].lock() = Slab::new(Self::MIN_SLAB_SIZE * 64);
    }
}

unsafe impl GlobalAlloc for SvsmAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let ret = match self.get_slab(size) {
            Some(slab) => slab.lock().allocate().map_err(|e| e.into()),
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
            PageInfo::Slab(_si) => {
                let slab = self.get_slab(size).expect("Invalid page info");
                slab.lock().deallocate(virt_addr);
            }
            _ => {
                panic!("Freeing memory on unsupported page type");
            }
        }
    }
}

#[cfg_attr(any(target_os = "none"), global_allocator)]
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
static ALLOCATOR: SvsmAllocator = SvsmAllocator::new();

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

#[cfg(test)]
pub const DEFAULT_TEST_MEMORY_SIZE: usize = 16usize * 1024 * 1024;

/// A dummy struct to acquire a lock over global memory for tests.
#[cfg(any(test, fuzzing))]
#[derive(Debug)]
#[allow(dead_code)]
pub struct TestRootMem<'a>(LockGuard<'a, ()>);

#[cfg(any(test, fuzzing))]
impl TestRootMem<'_> {
    #[cfg(test_in_svsm)]
    #[must_use = "memory guard must be held for the whole test"]
    pub fn setup(_size: usize) -> Self {
        // We do not need to set up root memory if running inside the SVSM.
        Self(TEST_ROOT_MEM_LOCK.lock())
    }

    /// Acquire a lock on global memory and initialize it
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

#[test]
fn test_root_mem_setup() {
    let test_mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
    drop(test_mem_lock);
}

#[test]
// Allocate one page and free it again, verify that memory_info() reflects it.
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
// Allocate and free all available compound pages, verify that memory_info()
// reflects it.
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
// Allocate and free all available 4k pages, verify that memory_info()
// reflects it.
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
// Allocate and free all available compound pages, verify that any subsequent
// allocation fails.
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

#[cfg(test)]
const TEST_SLAB_SIZES: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];

#[test]
// Allocate and free a couple of objects for each slab size.
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
            let n = (4 * PAGE_SIZE + size - 1) / size;
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
// Allocate enough objects so that the SlabPageSlab will need a SlabPage for
// itself twice.
fn test_slab_page_slab_for_self() {
    extern crate alloc;
    use alloc::vec::Vec;

    let _mem_lock = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);

    const OBJECT_SIZE: usize = TEST_SLAB_SIZES[0];
    const OBJECTS_PER_PAGE: usize = PAGE_SIZE / OBJECT_SIZE;

    const SLAB_PAGE_SIZE: usize = size_of::<SlabPage>();
    const SLAB_PAGES_PER_PAGE: usize = PAGE_SIZE / SLAB_PAGE_SIZE;

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
// Allocate enough objects to hit an OOM situation and verify null gets
// returned at some point.
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
    for _i in 0..((TEST_MEMORY_SIZE + OBJECT_SIZE - 1) / OBJECT_SIZE) {
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
