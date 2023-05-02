// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::utils::{align_up, zero_mem_region};
use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::ptr;
use log;

struct PageStorageType(u64);

// Support allocations up to order-5 (128kb)
pub const MAX_ORDER: usize = 6;

pub fn get_order(size: usize) -> usize {
    let mut val = (size - 1) >> PAGE_SHIFT;
    let mut order: usize = 0;

    loop {
        if val == 0 {
            break;
        }

        order += 1;
        val >>= 1;
    }

    order
}

impl PageStorageType {
    pub const fn new(t: u64) -> Self {
        PageStorageType(t)
    }

    fn encode_order(&self, order: usize) -> PageStorageType {
        PageStorageType(self.0 | ((order as u64) & PAGE_ORDER_MASK) << PAGE_TYPE_SHIFT)
    }

    fn encode_next(&self, next_page: usize) -> PageStorageType {
        PageStorageType(self.0 | (next_page as u64) << PAGE_FREE_NEXT_SHIFT)
    }

    fn encode_slab(slab: VirtAddr) -> Self {
        PageStorageType(PAGE_TYPE_SLABPAGE | (slab.bits() as u64) & PAGE_TYPE_SLABPAGE_MASK)
    }

    fn encode_refcount(&self, refcount: u64) -> PageStorageType {
        PageStorageType(self.0 | refcount << PAGE_TYPE_SHIFT)
    }
}

const PAGE_TYPE_SHIFT: u64 = 4;
const PAGE_TYPE_MASK: u64 = (1u64 << PAGE_TYPE_SHIFT) - 1;

const PAGE_TYPE_FREE: u64 = 0;
const PAGE_FREE_NEXT_SHIFT: u64 = 12;
const PAGE_FREE_NEXT_MASK: u64 = !((1u64 << PAGE_FREE_NEXT_SHIFT) - 1);

const PAGE_TYPE_ALLOCATED: u64 = 1;

const PAGE_ORDER_MASK: u64 = (1u64 << (PAGE_FREE_NEXT_SHIFT - PAGE_TYPE_SHIFT)) - 1;

// SLAB pages are always order-0
const PAGE_TYPE_SLABPAGE: u64 = 2;
const PAGE_TYPE_SLABPAGE_MASK: u64 = !PAGE_TYPE_MASK;

const PAGE_TYPE_COMPOUND: u64 = 3;

// File pages used for file and task data
const PAGE_TYPE_FILE: u64 = 4;

const PAGE_TYPE_RESERVED: u64 = (1u64 << PAGE_TYPE_SHIFT) - 1;

struct FreeInfo {
    next_page: usize,
    order: usize,
}

impl FreeInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_FREE)
            .encode_order(self.order)
            .encode_next(self.next_page)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        let next = ((mem.0 & PAGE_FREE_NEXT_MASK) >> PAGE_FREE_NEXT_SHIFT) as usize;
        let order = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        FreeInfo {
            next_page: next,
            order,
        }
    }
}

struct AllocatedInfo {
    order: usize,
}

impl AllocatedInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_ALLOCATED).encode_order(self.order)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        let order = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        AllocatedInfo { order }
    }
}

struct SlabPageInfo {
    slab: VirtAddr,
}

impl SlabPageInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::encode_slab(self.slab)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        SlabPageInfo {
            slab: VirtAddr::from(mem.0 & PAGE_TYPE_SLABPAGE_MASK),
        }
    }
}

struct CompoundInfo {
    order: usize,
}

impl CompoundInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_COMPOUND).encode_order(self.order)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        let order = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        CompoundInfo { order }
    }
}

struct ReservedInfo {}

impl ReservedInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_RESERVED)
    }

    pub fn decode(_mem: PageStorageType) -> Self {
        ReservedInfo {}
    }
}

struct FileInfo {
    /// Reference count
    ref_count: u64,
}

impl FileInfo {
    pub const fn new(ref_count: u64) -> Self {
        FileInfo { ref_count }
    }

    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_FILE).encode_refcount(self.ref_count)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        FileInfo {
            ref_count: (mem.0 >> PAGE_TYPE_SHIFT),
        }
    }
}

enum Page {
    Free(FreeInfo),
    Allocated(AllocatedInfo),
    SlabPage(SlabPageInfo),
    CompoundPage(CompoundInfo),
    FilePage(FileInfo),
    Reserved(ReservedInfo),
}

impl Page {
    pub fn to_mem(&self) -> PageStorageType {
        match self {
            Page::Free(fi) => fi.encode(),
            Page::Allocated(ai) => ai.encode(),
            Page::SlabPage(si) => si.encode(),
            Page::CompoundPage(ci) => ci.encode(),
            Page::FilePage(fi) => fi.encode(),
            Page::Reserved(ri) => ri.encode(),
        }
    }

    pub fn from_mem(mem: PageStorageType) -> Self {
        let page_type = mem.0 & PAGE_TYPE_MASK;

        if page_type == PAGE_TYPE_FREE {
            Page::Free(FreeInfo::decode(mem))
        } else if page_type == PAGE_TYPE_ALLOCATED {
            Page::Allocated(AllocatedInfo::decode(mem))
        } else if page_type == PAGE_TYPE_SLABPAGE {
            Page::SlabPage(SlabPageInfo::decode(mem))
        } else if page_type == PAGE_TYPE_COMPOUND {
            Page::CompoundPage(CompoundInfo::decode(mem))
        } else if page_type == PAGE_TYPE_FILE {
            Page::FilePage(FileInfo::decode(mem))
        } else if page_type == PAGE_TYPE_RESERVED {
            Page::Reserved(ReservedInfo::decode(mem))
        } else {
            panic!("Unknown Page Type {}", page_type);
        }
    }
}

pub struct MemInfo {
    pub total_pages: [usize; MAX_ORDER],
    pub free_pages: [usize; MAX_ORDER],
}

struct MemoryRegion {
    start_phys: PhysAddr,
    start_virt: VirtAddr,
    page_count: usize,
    nr_pages: [usize; MAX_ORDER],
    next_page: [usize; MAX_ORDER],
    free_pages: [usize; MAX_ORDER],
}

impl MemoryRegion {
    pub const fn new() -> Self {
        MemoryRegion {
            start_phys: PhysAddr::null(),
            start_virt: VirtAddr::null(),
            page_count: 0,
            nr_pages: [0; MAX_ORDER],
            next_page: [0; MAX_ORDER],
            free_pages: [0; MAX_ORDER],
        }
    }

    #[allow(dead_code)]
    pub fn phys_to_virt(&self, paddr: PhysAddr) -> Option<VirtAddr> {
        let end_phys = self.start_phys.offset(self.page_count * PAGE_SIZE);

        if paddr < self.start_phys || paddr >= end_phys {
            // For the initial stage2 identity mapping, the root page table
            // pages are static and outside of the heap memory region.
            if VirtAddr::from(self.start_phys.bits()) == self.start_virt {
                return Some(VirtAddr::from(paddr.bits()));
            }
            return None;
        }

        let offset = paddr - self.start_phys;

        Some(self.start_virt.offset(offset))
    }

    #[allow(dead_code)]
    pub fn virt_to_phys(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let end_virt = self.start_virt.offset(self.page_count * PAGE_SIZE);

        if vaddr < self.start_virt || vaddr >= end_virt {
            return None;
        }

        let offset = vaddr - self.start_virt;

        Some(self.start_phys.offset(offset))
    }

    fn page_info_virt_addr(&self, pfn: usize) -> VirtAddr {
        let size = size_of::<PageStorageType>();
        let virt = self.start_virt;
        virt.offset(pfn * size)
    }

    fn check_pfn(&self, pfn: usize) {
        if pfn >= self.page_count {
            panic!("Invalid Page Number {}", pfn);
        }
    }

    fn check_virt_addr(&self, vaddr: VirtAddr) -> bool {
        let start = self.start_virt;
        let end = self.start_virt.offset(self.page_count * PAGE_SIZE);

        vaddr >= start && vaddr < end
    }

    fn write_page_info(&self, pfn: usize, pi: Page) {
        self.check_pfn(pfn);

        let info: PageStorageType = pi.to_mem();
        unsafe {
            let ptr = self
                .page_info_virt_addr(pfn)
                .as_mut_ptr::<PageStorageType>();
            (*ptr) = info;
        }
    }

    fn read_page_info(&self, pfn: usize) -> Page {
        self.check_pfn(pfn);

        let virt = self.page_info_virt_addr(pfn).as_ptr::<u64>();
        let info = unsafe { PageStorageType(*virt) };

        Page::from_mem(info)
    }

    pub fn get_page_info(&self, vaddr: VirtAddr) -> Result<Page, SvsmError> {
        if vaddr.is_null() || !self.check_virt_addr(vaddr) {
            return Err(SvsmError::Mem);
        }

        let pfn = (vaddr - self.start_virt) / PAGE_SIZE;

        Ok(self.read_page_info(pfn))
    }

    fn get_next_page(&mut self, order: usize) -> Result<usize, SvsmError> {
        let pfn = self.next_page[order];

        if pfn == 0 {
            return Err(SvsmError::Mem);
        }

        let pg = self.read_page_info(pfn);

        let new_next = match pg {
            Page::Free(fi) => fi.next_page,
            _ => panic!("Unexpected page type in MemoryRegion::get_next_page()"),
        };

        self.next_page[order] = new_next;

        self.free_pages[order] -= 1;

        Ok(pfn)
    }

    fn init_compound_page(&mut self, pfn: usize, order: usize, next_pfn: usize) {
        let nr_pages: usize = 1 << order;

        let head = Page::Free(FreeInfo {
            next_page: next_pfn,
            order,
        });
        self.write_page_info(pfn, head);

        for i in 1..nr_pages {
            let compound = Page::CompoundPage(CompoundInfo { order });
            self.write_page_info(pfn + i, compound);
        }
    }

    fn split_page(&mut self, pfn: usize, order: usize) -> Result<(), SvsmError> {
        if order < 1 || order >= MAX_ORDER {
            return Err(SvsmError::Mem);
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

    fn refill_page_list(&mut self, order: usize) -> Result<(), SvsmError> {
        if self.next_page[order] != 0 {
            return Ok(());
        }

        if order >= MAX_ORDER - 1 {
            return Err(SvsmError::Mem);
        }

        self.refill_page_list(order + 1)?;

        let pfn = self.get_next_page(order + 1)?;

        self.split_page(pfn, order + 1)
    }

    pub fn allocate_pages(&mut self, order: usize) -> Result<VirtAddr, SvsmError> {
        self.refill_page_list(order)?;
        let pfn = self.get_next_page(order)?;
        let pg = Page::Allocated(AllocatedInfo { order });
        self.write_page_info(pfn, pg);
        Ok(self.start_virt.offset(pfn * PAGE_SIZE))
    }

    pub fn allocate_page(&mut self) -> Result<VirtAddr, SvsmError> {
        self.allocate_pages(0)
    }

    pub fn allocate_zeroed_page(&mut self) -> Result<VirtAddr, SvsmError> {
        let vaddr = self.allocate_page()?;

        zero_mem_region(vaddr, vaddr.offset(PAGE_SIZE));

        Ok(vaddr)
    }

    pub fn allocate_slab_page(&mut self, slab: Option<VirtAddr>) -> Result<VirtAddr, SvsmError> {
        self.refill_page_list(0)?;

        let slab_vaddr = slab.unwrap_or(VirtAddr::null());
        let pfn = self.get_next_page(0)?;
        assert_eq!(slab_vaddr.bits() & (PAGE_TYPE_MASK as usize), 0);
        let pg = Page::SlabPage(SlabPageInfo { slab: slab_vaddr });
        self.write_page_info(pfn, pg);
        Ok(self.start_virt.offset(pfn * PAGE_SIZE))
    }

    pub fn allocate_file_page(&mut self) -> Result<VirtAddr, SvsmError> {
        self.refill_page_list(0)?;
        let pfn = self.get_next_page(0)?;
        let pg = Page::FilePage(FileInfo::new(1));
        self.write_page_info(pfn, pg);
        Ok(self.start_virt.offset(pfn * PAGE_SIZE))
    }

    pub fn get_file_page(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let page = self.get_page_info(vaddr)?;

        match page {
            Page::FilePage(mut fi) => {
                let pfn = (vaddr - self.start_virt) / PAGE_SIZE;
                assert!(fi.ref_count > 0);
                fi.ref_count += 1;
                self.write_page_info(pfn, Page::FilePage(fi));
                Ok(())
            }
            _ => Err(SvsmError::Mem),
        }
    }

    pub fn put_file_page(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let page = self.get_page_info(vaddr)?;

        match page {
            Page::FilePage(mut fi) => {
                let pfn = (vaddr - self.start_virt) / PAGE_SIZE;
                assert!(fi.ref_count > 0);
                fi.ref_count -= 1;
                if fi.ref_count > 0 {
                    self.write_page_info(pfn, Page::FilePage(fi));
                } else {
                    self.free_page(vaddr)
                }
                Ok(())
            }
            _ => Err(SvsmError::Mem),
        }
    }

    fn compound_neighbor(&self, pfn: usize, order: usize) -> Result<usize, SvsmError> {
        if order >= MAX_ORDER - 1 {
            return Err(SvsmError::Mem);
        }

        assert_eq!(pfn & ((1usize << order) - 1), 0);
        let pfn = pfn ^ (1usize << order);
        if pfn >= self.page_count {
            return Err(SvsmError::Mem);
        }

        Ok(pfn)
    }

    fn merge_pages(&mut self, pfn1: usize, pfn2: usize, order: usize) -> Result<usize, SvsmError> {
        if order >= MAX_ORDER - 1 {
            return Err(SvsmError::Mem);
        }

        let nr_pages: usize = 1 << (order + 1);
        let pfn = if pfn1 < pfn2 { pfn1 } else { pfn2 };

        // Write new compound head
        let pg = Page::Allocated(AllocatedInfo { order: order + 1 });
        self.write_page_info(pfn, pg);

        // Write compound pages
        for i in 1..nr_pages {
            let pg = Page::CompoundPage(CompoundInfo { order: order + 1 });
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
        match page {
            Page::Free(fi) => fi.next_page,
            _ => {
                panic!("Unexpected page type in free-list for order {}", order);
            }
        }
    }

    fn allocate_pfn(&mut self, pfn: usize, order: usize) -> Result<(), SvsmError> {
        let first_pfn = self.next_page[order];

        // Handle special cases first
        if first_pfn == 0 {
            // No pages for that order
            return Err(SvsmError::Mem);
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
                break;
            } else if current_pfn == pfn {
                let next_pfn = self.next_free_pfn(current_pfn, order);
                let pg = Page::Free(FreeInfo {
                    next_page: next_pfn,
                    order,
                });
                self.write_page_info(old_pfn, pg);

                let pg = Page::Allocated(AllocatedInfo { order });
                self.write_page_info(current_pfn, pg);

                self.free_pages[order] -= 1;

                return Ok(());
            }

            old_pfn = current_pfn;
        }

        Err(SvsmError::Mem)
    }

    fn free_page_raw(&mut self, pfn: usize, order: usize) {
        let old_next = self.next_page[order];
        let pg = Page::Free(FreeInfo {
            next_page: old_next,
            order,
        });

        self.write_page_info(pfn, pg);
        self.next_page[order] = pfn;

        self.free_pages[order] += 1;
    }

    fn try_to_merge_page(&mut self, pfn: usize, order: usize) -> Result<usize, SvsmError> {
        let neighbor_pfn = self.compound_neighbor(pfn, order)?;
        let neighbor_page = self.read_page_info(neighbor_pfn);

        if let Page::Free(fi) = neighbor_page {
            if fi.order != order {
                return Err(SvsmError::Mem);
            }

            self.allocate_pfn(neighbor_pfn, order)?;

            let new_pfn = self.merge_pages(pfn, neighbor_pfn, order)?;

            Ok(new_pfn)
        } else {
            Err(SvsmError::Mem)
        }
    }

    fn free_page_order(&mut self, pfn: usize, order: usize) {
        match self.try_to_merge_page(pfn, order) {
            Err(_e) => {
                self.free_page_raw(pfn, order);
            }
            Ok(new_pfn) => {
                self.free_page_order(new_pfn, order + 1);
            }
        }
    }

    pub fn free_page(&mut self, vaddr: VirtAddr) {
        let res = self.get_page_info(vaddr);

        if let Err(_e) = res {
            return;
        }

        let pfn = (vaddr - self.start_virt) / PAGE_SIZE;

        match res.unwrap() {
            Page::Allocated(ai) => {
                self.free_page_order(pfn, ai.order);
            }
            Page::SlabPage(_si) => {
                self.free_page_order(pfn, 0);
            }
            Page::CompoundPage(ci) => {
                let mask = (1usize << ci.order) - 1;
                let start_pfn = pfn & !mask;
                self.free_page_order(start_pfn, ci.order);
            }
            Page::FilePage(_) => {
                self.free_page_order(pfn, 0);
            }
            _ => {
                panic!("Unexpected page type in MemoryRegion::free_page()");
            }
        }
    }

    pub fn memory_info(&self) -> MemInfo {
        MemInfo {
            total_pages: self.nr_pages,
            free_pages: self.free_pages,
        }
    }

    pub fn init_memory(&mut self) {
        let size = size_of::<PageStorageType>();
        let meta_pages = align_up(self.page_count * size, PAGE_SIZE) / PAGE_SIZE;

        /* Mark page storage as reserved */
        for i in 0..meta_pages {
            let pg: Page = Page::Reserved(ReservedInfo {});
            self.write_page_info(i, pg);
        }

        self.nr_pages[0] = self.page_count - meta_pages;

        /* Mark all pages as allocated */
        for i in meta_pages..self.page_count {
            let pg = Page::Allocated(AllocatedInfo { order: 0 });
            self.write_page_info(i, pg);
        }

        /* Now free all pages */
        for i in meta_pages..self.page_count {
            self.free_page_order(i, 0);
        }
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
    ROOT_MEM.lock().allocate_page()
}

pub fn allocate_pages(order: usize) -> Result<VirtAddr, SvsmError> {
    ROOT_MEM.lock().allocate_pages(order)
}

pub fn allocate_slab_page(slab: Option<VirtAddr>) -> Result<VirtAddr, SvsmError> {
    ROOT_MEM.lock().allocate_slab_page(slab)
}

pub fn allocate_zeroed_page() -> Result<VirtAddr, SvsmError> {
    ROOT_MEM.lock().allocate_zeroed_page()
}

pub fn allocate_file_page() -> Result<VirtAddr, SvsmError> {
    ROOT_MEM.lock().allocate_file_page()
}

pub fn get_file_page(vaddr: VirtAddr) -> Result<(), SvsmError> {
    ROOT_MEM.lock().get_file_page(vaddr)
}

pub fn put_file_page(vaddr: VirtAddr) -> Result<(), SvsmError> {
    ROOT_MEM.lock().put_file_page(vaddr)
}

pub fn free_page(vaddr: VirtAddr) {
    ROOT_MEM.lock().free_page(vaddr)
}

pub fn memory_info() -> MemInfo {
    ROOT_MEM.lock().memory_info()
}

struct SlabPage {
    vaddr: VirtAddr,
    capacity: u16,
    free: u16,
    item_size: u16,
    used_bitmap: [u64; 2],
    next_page: VirtAddr,
}

impl SlabPage {
    pub const fn new() -> Self {
        SlabPage {
            vaddr: VirtAddr::null(),
            capacity: 0,
            free: 0,
            item_size: 0,
            used_bitmap: [0; 2],
            next_page: VirtAddr::null(),
        }
    }

    pub fn init(
        &mut self,
        slab_vaddr: Option<VirtAddr>,
        mut item_size: u16,
    ) -> Result<(), SvsmError> {
        if self.item_size != 0 {
            return Ok(());
        }

        assert!(item_size <= (PAGE_SIZE / 2) as u16);
        assert!(self.vaddr.is_null());

        if item_size < 32 {
            item_size = 32;
        }

        let vaddr = allocate_slab_page(slab_vaddr)?;
        self.vaddr = vaddr;
        self.item_size = item_size;
        self.capacity = (PAGE_SIZE as u16) / item_size;
        self.free = self.capacity;

        Ok(())
    }

    pub fn destroy(&mut self) {
        if self.vaddr.is_null() {
            return;
        }

        free_page(self.vaddr);
    }

    pub fn get_capacity(&self) -> u16 {
        self.capacity
    }

    pub fn get_free(&self) -> u16 {
        self.free
    }

    pub fn get_next_page(&self) -> VirtAddr {
        self.next_page
    }

    pub fn set_next_page(&mut self, next_page: VirtAddr) {
        self.next_page = next_page;
    }

    pub fn allocate(&mut self) -> Result<VirtAddr, SvsmError> {
        if self.free == 0 {
            return Err(SvsmError::Mem);
        }

        for i in 0..self.capacity {
            let idx = (i / 64) as usize;
            let mask = 1u64 << (i % 64);

            if self.used_bitmap[idx] & mask == 0 {
                self.used_bitmap[idx] |= mask;
                self.free -= 1;
                return Ok(self.vaddr.offset((self.item_size * i) as usize));
            }
        }

        Err(SvsmError::Mem)
    }

    pub fn free(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        if vaddr < self.vaddr || vaddr >= self.vaddr.offset(PAGE_SIZE) {
            return Err(SvsmError::Mem);
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
        SlabCommon {
            item_size,
            capacity: 0,
            free: 0,
            pages: 0,
            full_pages: 0,
            free_pages: 0,
            page: SlabPage::new(),
        }
    }

    fn init(&mut self, slab_vaddr: Option<VirtAddr>) -> Result<(), SvsmError> {
        if let Err(_e) = self.page.init(slab_vaddr, self.item_size) {
            return Err(SvsmError::Mem);
        }

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

    fn remove_slab_page(&mut self, prev_page: &mut SlabPage, old_page: &SlabPage) {
        let capacity = old_page.get_capacity() as u32;
        self.pages -= 1;
        self.free_pages -= 1;
        self.capacity -= capacity;
        self.free -= capacity;

        prev_page.set_next_page(old_page.get_next_page());
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

            let next_page = (*page).get_next_page();
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
}

struct SlabPageSlab {
    common: SlabCommon,
}

impl SlabPageSlab {
    const fn new() -> Self {
        SlabPageSlab {
            common: SlabCommon::new(size_of::<SlabPage>() as u16),
        }
    }

    fn init(&mut self) -> Result<(), SvsmError> {
        self.common.init(None)
    }

    fn grow_slab(&mut self) -> Result<(), SvsmError> {
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
        if let Err(_e) = slab_page.init(None, self.common.item_size) {
            self.common.deallocate_slot(page_vaddr);
            return Err(SvsmError::Mem);
        }

        self.common.add_slab_page(slab_page);

        Ok(())
    }

    fn shrink_slab(&mut self) {
        // The SlabPageSlab uses SlabPages on its own and freeing a SlabPage can empty another SlabPage.
        while self.common.free_pages > 1 {
            let mut last_page = &mut self.common.page as *mut SlabPage;
            let mut next_page_vaddr = self.common.page.get_next_page();
            let mut freed_one = false;
            loop {
                if next_page_vaddr.is_null() {
                    break;
                }
                let slab_page = unsafe { &mut *next_page_vaddr.as_mut_ptr::<SlabPage>() };
                next_page_vaddr = slab_page.get_next_page();

                let capacity = slab_page.get_capacity();
                let free = slab_page.get_free();
                if free == capacity {
                    self.common
                        .remove_slab_page(unsafe { &mut *last_page }, slab_page);
                    slab_page.destroy();
                    self.common
                        .deallocate_slot(VirtAddr::from(slab_page as *mut SlabPage));
                    freed_one = true;
                } else {
                    last_page = slab_page;
                }
            }
            assert!(freed_one);
        }
    }

    fn allocate(&mut self) -> Result<*mut SlabPage, SvsmError> {
        if self.grow_slab().is_err() {
            return Err(SvsmError::Mem);
        }

        Ok(unsafe { &mut *self.common.allocate_slot().as_mut_ptr::<SlabPage>() })
    }

    fn deallocate(&mut self, slab_page: *mut SlabPage) {
        self.common.deallocate_slot(VirtAddr::from(slab_page));
        self.shrink_slab();
    }
}

struct Slab {
    common: SlabCommon,
}

impl Slab {
    const fn new(item_size: u16) -> Self {
        Slab {
            common: SlabCommon::new(item_size),
        }
    }

    fn init(&mut self) -> Result<(), SvsmError> {
        let slab_vaddr = VirtAddr::from(self as *mut Slab);
        self.common.init(Some(slab_vaddr))
    }

    fn grow_slab(&mut self) -> Result<(), SvsmError> {
        if self.common.capacity == 0 {
            if let Err(_e) = self.init() {
                return Err(SvsmError::Mem);
            }
            return Ok(());
        }

        if self.common.free != 0 {
            return Ok(());
        }

        let slab_page = match SLAB_PAGE_SLAB.lock().allocate() {
            Ok(slab_page) => unsafe { &mut *slab_page },
            Err(_) => return Err(SvsmError::Mem),
        };
        let slab_vaddr = VirtAddr::from(self as *mut Slab);
        *slab_page = SlabPage::new();
        if let Err(_e) = slab_page.init(Some(slab_vaddr), self.common.item_size) {
            SLAB_PAGE_SLAB.lock().deallocate(slab_page);
            return Err(SvsmError::Mem);
        }

        self.common.add_slab_page(&mut *slab_page);
        Ok(())
    }

    fn shrink_slab(&mut self) {
        let mut last_page = &mut self.common.page as *mut SlabPage;
        let mut next_page_vaddr = self.common.page.get_next_page();
        let mut freed_one = false;

        if self.common.free_pages <= 1 {
            return;
        } else if 2 * self.common.free < self.common.capacity {
            return;
        }

        loop {
            if next_page_vaddr.is_null() {
                break;
            }
            let slab_page = unsafe { &mut *(next_page_vaddr.as_mut_ptr::<SlabPage>()) };
            next_page_vaddr = slab_page.get_next_page();

            let capacity = slab_page.get_capacity();
            let free = slab_page.get_free();
            if free == capacity {
                self.common
                    .remove_slab_page(unsafe { &mut *last_page }, slab_page);
                slab_page.destroy();
                SLAB_PAGE_SLAB.lock().deallocate(slab_page);
                freed_one = true;
                break;
            } else {
                last_page = slab_page;
            }
        }
        assert!(freed_one);
    }

    fn allocate(&mut self) -> Result<VirtAddr, SvsmError> {
        if let Err(_e) = self.grow_slab() {
            return Err(SvsmError::Mem);
        }

        Ok(self.common.allocate_slot())
    }

    fn deallocate(&mut self, vaddr: VirtAddr) {
        self.common.deallocate_slot(vaddr);
        self.shrink_slab();
    }
}

static SLAB_PAGE_SLAB: SpinLock<SlabPageSlab> = SpinLock::new(SlabPageSlab::new());

pub struct SvsmAllocator {
    slab_size_32: SpinLock<Slab>,
    slab_size_64: SpinLock<Slab>,
    slab_size_128: SpinLock<Slab>,
    slab_size_256: SpinLock<Slab>,
    slab_size_512: SpinLock<Slab>,
    slab_size_1024: SpinLock<Slab>,
    slab_size_2048: SpinLock<Slab>,
}

impl SvsmAllocator {
    pub const fn new() -> Self {
        SvsmAllocator {
            slab_size_32: SpinLock::new(Slab::new(32)),
            slab_size_64: SpinLock::new(Slab::new(64)),
            slab_size_128: SpinLock::new(Slab::new(128)),
            slab_size_256: SpinLock::new(Slab::new(256)),
            slab_size_512: SpinLock::new(Slab::new(512)),
            slab_size_1024: SpinLock::new(Slab::new(1024)),
            slab_size_2048: SpinLock::new(Slab::new(2048)),
        }
    }
}

unsafe impl GlobalAlloc for SvsmAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret: Result<VirtAddr, SvsmError>;
        let size = layout.size();

        if size <= 32 {
            ret = self.slab_size_32.lock().allocate();
        } else if size <= 64 {
            ret = self.slab_size_64.lock().allocate();
        } else if size <= 128 {
            ret = self.slab_size_128.lock().allocate();
        } else if size <= 256 {
            ret = self.slab_size_256.lock().allocate();
        } else if size <= 512 {
            ret = self.slab_size_512.lock().allocate();
        } else if size <= 1024 {
            ret = self.slab_size_1024.lock().allocate();
        } else if size <= 2048 {
            ret = self.slab_size_2048.lock().allocate();
        } else if size <= 4096 {
            ret = allocate_page();
        } else {
            let order = get_order(size);
            if order >= MAX_ORDER {
                return ptr::null_mut();
            }
            ret = allocate_pages(order);
        }

        if let Err(_e) = ret {
            return ptr::null_mut();
        }

        ret.unwrap().as_mut_ptr::<u8>()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let virt_addr = VirtAddr::from(ptr);

        let result = ROOT_MEM.lock().get_page_info(virt_addr);

        if let Err(_e) = result {
            panic!("Freeing unknown memory");
        }

        let info = result.unwrap();

        match info {
            Page::Allocated(_ai) => {
                free_page(virt_addr);
            }
            Page::SlabPage(si) => {
                assert!(!si.slab.is_null());
                let slab = si.slab.as_mut_ptr::<Slab>();

                (*slab).deallocate(virt_addr);
            }
            _ => {
                panic!("Freeing memory on unsupported page type");
            }
        }
    }
}

#[cfg_attr(not(test), global_allocator)]
pub static mut ALLOCATOR: SvsmAllocator = SvsmAllocator::new();

pub fn root_mem_init(pstart: PhysAddr, vstart: VirtAddr, page_count: usize) {
    {
        let mut region = ROOT_MEM.lock();
        region.start_phys = pstart;
        region.start_virt = vstart;
        region.page_count = page_count;
        region.init_memory();
        // drop lock here so slab initialization does not deadlock
    }

    if let Err(_e) = SLAB_PAGE_SLAB.lock().init() {
        panic!("Failed to initialize SLAB_PAGE_SLAB");
    }
}

pub fn print_alloc_info() {
    for i in 0..MAX_ORDER {
        let nr_pages = ROOT_MEM.lock().nr_pages[i];
        let free_pages = ROOT_MEM.lock().free_pages[i];
        log::trace!(
            "Order-{}: Pages: {:#04} Free Pages: {:#04}",
            i,
            nr_pages,
            free_pages
        );
    }
}

#[cfg(test)]
static TEST_ROOT_MEM_LOCK: SpinLock<()> = SpinLock::new(());

#[cfg(test)]
use crate::locking::LockGuard;

#[cfg(test)]
// Allocate a memory region from the standard Rust allocator and pass it to
// root_mem_init().
fn setup_test_root_mem(size: usize) -> LockGuard<'static, ()> {
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
    let lock = TEST_ROOT_MEM_LOCK.lock();
    let vaddr = VirtAddr::from(ptr);
    let paddr = PhysAddr::from(vaddr.bits()); // Identity mapping
    root_mem_init(paddr, vaddr, page_count);
    lock
}

#[cfg(test)]
// Undo the setup done from setup_test_root_mem().
fn destroy_test_root_mem(lock: LockGuard<'static, ()>) {
    extern crate alloc;
    use alloc::alloc::dealloc;

    let mut root_mem = ROOT_MEM.lock();
    let layout = Layout::from_size_align(root_mem.page_count * PAGE_SIZE, PAGE_SIZE).unwrap();
    unsafe { dealloc(root_mem.start_virt.as_mut_ptr::<u8>(), layout) };
    *root_mem = MemoryRegion::new();

    // Reset the Slabs
    *SLAB_PAGE_SLAB.lock() = SlabPageSlab::new();
    unsafe { ALLOCATOR = SvsmAllocator::new() };

    drop(lock);
}

#[cfg(test)]
const DEFAULT_TEST_MEMORY_SIZE: usize = 16usize * 1024 * 1024;

#[test]
fn test_root_mem_setup() {
    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
    destroy_test_root_mem(test_mem_lock);
}

#[test]
// Allocate one page and free it again, verify that memory_info() reflects it.
fn test_page_alloc_one() {
    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
    let mut root_mem = ROOT_MEM.lock();

    let info_before = root_mem.memory_info();
    let page = root_mem.allocate_page().unwrap();
    assert!(!page.is_null());
    assert_ne!(info_before.free_pages, root_mem.memory_info().free_pages);
    root_mem.free_page(page);
    assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);

    drop(root_mem);
    destroy_test_root_mem(test_mem_lock);
}

#[test]
// Allocate and free all available compound pages, verify that memory_info()
// reflects it.
fn test_page_alloc_all_compound() {
    extern crate alloc;
    use alloc::vec::Vec;

    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
    let mut root_mem = ROOT_MEM.lock();

    let info_before = root_mem.memory_info();
    let mut allocs: [Vec<VirtAddr>; MAX_ORDER] = Default::default();
    for o in 0..MAX_ORDER {
        for _i in 0..info_before.free_pages[o] {
            let pages = root_mem.allocate_pages(o).unwrap();
            assert!(!pages.is_null());
            allocs[o].push(pages);
        }
    }
    let info_after = root_mem.memory_info();
    for o in 0..MAX_ORDER {
        assert_eq!(info_after.free_pages[o], 0);
    }

    for o in 0..MAX_ORDER {
        for pages in &allocs[o][..] {
            root_mem.free_page(*pages);
        }
    }
    assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);

    drop(root_mem);
    destroy_test_root_mem(test_mem_lock);
}

#[test]
// Allocate and free all available 4k pages, verify that memory_info()
// reflects it.
fn test_page_alloc_all_single() {
    extern crate alloc;
    use alloc::vec::Vec;

    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
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

    drop(root_mem);
    destroy_test_root_mem(test_mem_lock);
}

#[test]
// Allocate and free all available compound pages, verify that any subsequent
// allocation fails.
fn test_page_alloc_oom() {
    extern crate alloc;
    use alloc::vec::Vec;

    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
    let mut root_mem = ROOT_MEM.lock();

    let info_before = root_mem.memory_info();
    let mut allocs: [Vec<VirtAddr>; MAX_ORDER] = Default::default();
    for o in 0..MAX_ORDER {
        for _i in 0..info_before.free_pages[o] {
            let pages = root_mem.allocate_pages(o).unwrap();
            assert!(!pages.is_null());
            allocs[o].push(pages);
        }
    }
    let info_after = root_mem.memory_info();
    for o in 0..MAX_ORDER {
        assert_eq!(info_after.free_pages[o], 0);
    }

    let page = root_mem.allocate_page();
    if let Ok(_) = page {
        panic!("unexpected page allocation success after memory exhaustion");
    }

    for o in 0..MAX_ORDER {
        for pages in &allocs[o][..] {
            root_mem.free_page(*pages);
        }
    }
    assert_eq!(info_before.free_pages, root_mem.memory_info().free_pages);

    drop(root_mem);
    destroy_test_root_mem(test_mem_lock);
}

#[test]
fn test_page_file() {
    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);
    let mut root_mem = ROOT_MEM.lock();

    // Allocate page and check ref-count
    let vaddr = root_mem.allocate_file_page().unwrap();
    let info = root_mem.get_page_info(vaddr).unwrap();

    match info {
        Page::FilePage(fi) => assert!(fi.ref_count == 1),
        _ => assert!(false),
    }

    // Get another reference and check ref-count
    root_mem.get_file_page(vaddr).expect("Not a file page");
    let info = root_mem.get_page_info(vaddr).unwrap();

    match info {
        Page::FilePage(fi) => assert!(fi.ref_count == 2),
        _ => assert!(false),
    }

    // Drop reference and check ref-count
    root_mem.put_file_page(vaddr).expect("Not a file page");
    let info = root_mem.get_page_info(vaddr).unwrap();

    match info {
        Page::FilePage(fi) => assert!(fi.ref_count == 1),
        _ => assert!(false),
    }

    // Drop last reference and check if page is released
    root_mem.put_file_page(vaddr).expect("Not a file page");
    let info = root_mem.get_page_info(vaddr).unwrap();

    match info {
        Page::Free(_) => assert!(true),
        _ => assert!(false),
    }

    drop(root_mem);
    destroy_test_root_mem(test_mem_lock);
}

#[cfg(test)]
const TEST_SLAB_SIZES: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];

#[test]
// Allocate and free a couple of objects for each slab size.
fn test_slab_alloc_free_many() {
    extern crate alloc;
    use alloc::vec::Vec;

    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);

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
            j = j + 1;
        }

        j = 0;
        for size in TEST_SLAB_SIZES {
            let layout = Layout::from_size_align(size, size).unwrap().pad_to_align();
            assert_eq!(layout.size(), size);

            for p in &allocs[j][..] {
                unsafe { ALLOCATOR.dealloc(*p, layout) };
            }
            j = j + 1;
        }
    }

    destroy_test_root_mem(test_mem_lock);
}

#[test]
// Allocate enough objects so that the SlabPageSlab will need a SlabPage for
// itself twice.
fn test_slab_page_slab_for_self() {
    extern crate alloc;
    use alloc::vec::Vec;

    let test_mem_lock = setup_test_root_mem(DEFAULT_TEST_MEMORY_SIZE);

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

    destroy_test_root_mem(test_mem_lock);
}

#[test]
// Allocate enough objects to hit an OOM situation and verify null gets
// returned at some point.
fn test_slab_oom() {
    extern crate alloc;
    use alloc::vec::Vec;

    const TEST_MEMORY_SIZE: usize = 256 * PAGE_SIZE;
    let test_mem_lock = setup_test_root_mem(TEST_MEMORY_SIZE);

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

    destroy_test_root_mem(test_mem_lock);
}
