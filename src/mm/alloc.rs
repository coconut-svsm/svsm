// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PhysAddr, PAGE_SIZE, PAGE_SHIFT};
use crate::kernel_launch::KernelLaunchInfo;
use core::alloc::{GlobalAlloc, Layout};
use crate::locking::SpinLock;
use crate::util::align_up;
use core::mem::size_of;
use crate::heap_start;
use core::arch::asm;
use core::ptr;

struct PageStorageType (u64);

// Support only order 0 allocations for now
pub const MAX_ORDER : usize = 6;

impl PageStorageType {
    pub const fn new(t : u64) -> Self {
        PageStorageType ( t )
    }

    fn encode_order(&self, order : usize) -> PageStorageType {
        PageStorageType ( self.0 | ((order as u64) & PAGE_ORDER_MASK) << PAGE_TYPE_SHIFT )
    }

    fn encode_next(&self, next_page : usize) -> PageStorageType {
        PageStorageType ( self.0 | (next_page as u64) << PAGE_FREE_NEXT_SHIFT )
    }

    fn encode_slab(slab : VirtAddr) -> Self {
        PageStorageType ( PAGE_TYPE_SLABPAGE | (slab as u64) & PAGE_TYPE_SLABPAGE_MASK )
    }
}

const PAGE_TYPE_SHIFT       : u64 = 4;
const PAGE_TYPE_MASK        : u64 = (1u64 << PAGE_TYPE_SHIFT) - 1;

const PAGE_TYPE_FREE        : u64 = 0;
const PAGE_FREE_NEXT_SHIFT  : u64 = 12;
const PAGE_FREE_NEXT_MASK   : u64 = !((1u64 << PAGE_FREE_NEXT_SHIFT) - 1);

const PAGE_TYPE_ALLOCATED   : u64 = 1;

const PAGE_ORDER_MASK       : u64 = (1u64 << (PAGE_FREE_NEXT_SHIFT - PAGE_TYPE_SHIFT)) - 1;

// SLAB pages are always order-0
const PAGE_TYPE_SLABPAGE    : u64 = 2;
const PAGE_TYPE_SLABPAGE_MASK   : u64 = !PAGE_TYPE_MASK;

const PAGE_TYPE_COMPOUND    : u64 = 3;

const PAGE_TYPE_RESERVED    : u64 = (1u64 << PAGE_TYPE_SHIFT) - 1;

struct FreeInfo {
    next_page   : usize,
    order       : usize,
}

impl FreeInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_FREE).encode_order(self.order).encode_next(self.next_page)
    }

    pub fn decode(mem : PageStorageType) -> Self {
        let next  = ((mem.0 & PAGE_FREE_NEXT_MASK) >> PAGE_FREE_NEXT_SHIFT) as usize;
        let order = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        FreeInfo { next_page : next, order : order }
    }
}

struct AllocatedInfo {
    order       : usize,
}

impl AllocatedInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_ALLOCATED).encode_order(self.order)
    }

    pub fn decode(mem : PageStorageType) -> Self {
        let order = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        AllocatedInfo { order : order }
    }
}

struct SlabPageInfo {
    slab : VirtAddr,
}

impl SlabPageInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::encode_slab(self.slab)
    }

    pub fn decode(mem : PageStorageType) -> Self {
        SlabPageInfo { slab : (mem.0 & PAGE_TYPE_SLABPAGE_MASK) as VirtAddr }
    }
}

struct CompoundInfo{
    order       : usize,
}

impl CompoundInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_COMPOUND).encode_order(self.order)
    }

    pub fn decode(mem : PageStorageType) -> Self {
        let order = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        CompoundInfo { order : order }
    }
}

struct ReservedInfo {
}

impl ReservedInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_RESERVED)
    }

    pub fn decode(_mem : PageStorageType) -> Self {
         ReservedInfo { }
    }
}

enum Page {
    Free(FreeInfo),
    Allocated(AllocatedInfo),
    SlabPage(SlabPageInfo),
    CompoundPage(CompoundInfo),
    Reserved(ReservedInfo),
}

impl Page {
    pub fn to_mem(&self) -> PageStorageType {
        match self {
            Page::Free(fi)          => { fi.encode() }
            Page::Allocated(ai)     => { ai.encode() }
            Page::SlabPage(si)      => { si.encode() }
            Page::CompoundPage(ci)  => { ci.encode() }
            Page::Reserved(ri)      => { ri.encode() }

        }
    }

    pub fn from_mem(mem : PageStorageType) -> Self {
        let page_type = mem.0 & PAGE_TYPE_MASK;

        if page_type == PAGE_TYPE_FREE {
            Page::Free(FreeInfo::decode(mem))
        } else if page_type == PAGE_TYPE_ALLOCATED {
            Page::Allocated(AllocatedInfo::decode(mem))
        } else if page_type == PAGE_TYPE_SLABPAGE {
            Page::SlabPage(SlabPageInfo::decode(mem))
        } else if page_type == PAGE_TYPE_COMPOUND {
            Page::CompoundPage(CompoundInfo::decode(mem))
        } else if page_type == PAGE_TYPE_RESERVED {
            Page::Reserved(ReservedInfo::decode(mem))
        } else {
            panic!("Unknown Page Type {}", page_type);
        }
    }
}

pub struct MemInfo {
    pub total_pages : [usize; MAX_ORDER],
    pub free_pages  : [usize; MAX_ORDER],
}

struct MemoryRegion {
    start_phys  : PhysAddr,
    start_virt  : VirtAddr,
    page_count  : usize,
    nr_pages    : [usize; MAX_ORDER],
    next_page   : [usize; MAX_ORDER],
    free_pages  : [usize; MAX_ORDER],
}

impl MemoryRegion {
    pub const fn new() -> Self {
        MemoryRegion {
            start_phys : 0,
            start_virt : 0,
            page_count : 0,
            nr_pages   : [0; MAX_ORDER],
            next_page  : [0; MAX_ORDER],
            free_pages : [0; MAX_ORDER],
        }
    }

    pub fn phys_to_virt(&self, paddr : PhysAddr) -> Option<VirtAddr> {
        let end_phys = self.start_phys + (self.page_count * PAGE_SIZE);

        if paddr < self.start_phys || paddr >= end_phys {
            return None;
        }

        let offset = paddr - self.start_phys;

        Some((self.start_virt + offset) as VirtAddr)
    }

    pub fn virt_to_phys(&self, vaddr : VirtAddr) -> Option<PhysAddr> {
        let end_virt = self.start_virt + (self.page_count * PAGE_SIZE);

        if vaddr < self.start_virt || vaddr >= end_virt {
            return None;
        }

        let offset = vaddr - self.start_virt;

        Some((self.start_phys + offset) as PhysAddr)
    }

    fn page_info_virt_addr(&self, pfn : usize) -> VirtAddr {
        let size = size_of::<PageStorageType>();
        let virt = self.start_virt;
        virt + ((pfn as usize) * size)
    }

    fn check_pfn(&self, pfn : usize) {
        if pfn >= self.page_count {
            panic!("Invalid Page Number {}", pfn);
        }
    }

    fn check_virt_addr(&self, vaddr : VirtAddr) -> bool {
        let start = self.start_virt;
        let end   = self.start_virt + (self.page_count * PAGE_SIZE);

        vaddr >= start && vaddr < end
    }

    fn write_page_info(&self, pfn : usize, pi : Page) {
        self.check_pfn(pfn);

        let info : PageStorageType = pi.to_mem();
        unsafe {
            let ptr : *mut PageStorageType = self.page_info_virt_addr(pfn) as *mut PageStorageType;
            (*ptr) = info;
        }
    }

    fn read_page_info(&self, pfn : usize) -> Page {
        self.check_pfn(pfn);

        let virt = self.page_info_virt_addr(pfn);
        let info : PageStorageType = PageStorageType ( unsafe { *(virt as *const u64) } );

        Page::from_mem(info)
    }

    pub fn get_page_info(&self, vaddr : VirtAddr) -> Result<Page, ()> {
        if vaddr == 0 || !self.check_virt_addr(vaddr) {
            return Err(());
        }

        let pfn = (vaddr - self.start_virt) / PAGE_SIZE;

        Ok(self.read_page_info(pfn))
    }

    fn get_next_page(&mut self, order : usize) -> Result<usize, ()> {
        let pfn = self.next_page[order];

        if pfn == 0 {
            return Err(());
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

    fn init_compound_page(&mut self, pfn : usize, order : usize, next_pfn : usize) {
        let nr_pages : usize = 1 << order;

        let head = Page::Free( FreeInfo { next_page : next_pfn, order : order } );
        self.write_page_info(pfn, head);

        for i in 1..nr_pages {
            let compound = Page::CompoundPage( CompoundInfo { order : order } );
            self.write_page_info(pfn + i, compound);
        }
    }

    fn split_page(&mut self, pfn : usize, order : usize) -> Result<(), ()> {
        if order < 1 || order >= MAX_ORDER {
            return Err(());
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

    fn refill_page_list(&mut self, order : usize) -> Result<(), ()> {
        if self.next_page[order] != 0 {
            return Ok(())
        }
        
        if order >= MAX_ORDER - 1 {
            return Err(());
        }

        self.refill_page_list(order + 1)?;

        let pfn = self.get_next_page(order + 1)?;

        self.split_page(pfn, order + 1)
    }

    pub fn allocate_pages(&mut self, order : usize) -> Result<VirtAddr, ()> {
        self.refill_page_list(order)?;
        if let Ok(pfn) = self.get_next_page(order) {
            let pg = Page::Allocated( AllocatedInfo { order : order } );
            self.write_page_info(pfn, pg);
            let vaddr = self.start_virt + (pfn * PAGE_SIZE);
            return Ok(vaddr);
        } else {
            return Err(());
        }
    }

    pub fn allocate_page(&mut self) -> Result<VirtAddr, ()> {
        self.allocate_pages(0)
    }

    pub fn allocate_zeroed_page(&mut self) -> Result<VirtAddr, ()> {
        let vaddr = self.allocate_page();

        if let Err(_e) = vaddr {
            return Err(());
        }

        unsafe {
            asm!("rep stosq",
                in("rdi") vaddr.unwrap(),
                in("rax") 0,
                in("rcx") PAGE_SIZE / 8,
                options(att_syntax));
        }

        vaddr
    }

    pub fn allocate_slab_page(&mut self, slab : Option<VirtAddr>) -> Result<VirtAddr, ()> {
        self.refill_page_list(0)?;

        let slab_vaddr = match slab {
            Some(slab_vaddr) => slab_vaddr,
            None => 0,
        };
        if let Ok(pfn) = self.get_next_page(0) {
            assert!(slab_vaddr & (PAGE_TYPE_MASK as usize) == 0);
            let pg = Page::SlabPage( SlabPageInfo { slab : slab_vaddr } );
            self.write_page_info(pfn, pg);
            let vaddr = self.start_virt + (pfn * PAGE_SIZE);
            return Ok(vaddr);
        } else {
            return Err(());
        }

    }

    fn order_mask(order : usize) -> usize {
        !((PAGE_SIZE << order) - 1)
    }

    fn pfn_to_virt(&self, pfn : usize) -> VirtAddr {
        self.start_virt + (pfn * PAGE_SIZE)
    }

    fn virt_to_pfn(&self, vaddr : VirtAddr) -> usize {
        (vaddr - self.start_virt) / PAGE_SIZE
    }

    fn compound_neighbor(&self, pfn : usize, order : usize) -> Result<usize, ()> {
        if order >= MAX_ORDER - 1 {
            return Err(());
        }

		let vaddr = self.pfn_to_virt(pfn) & MemoryRegion::order_mask(order);
		let neigh = vaddr ^ (PAGE_SIZE << order);

		if vaddr < self.start_virt || neigh < self.start_virt {
			return Err(());
		}

		let pfn = self.virt_to_pfn(neigh);
		if pfn >= self.page_count {
			return Err(());
		}

		Ok(pfn)
    }

    fn merge_pages(&mut self, pfn1 : usize, pfn2 : usize, order : usize) -> Result<usize, ()> {
        if order >= MAX_ORDER - 1 {
            return Err(());
        }

        let nr_pages : usize = 1 << order + 1;
        let pfn = if pfn1 < pfn2 { pfn1 } else { pfn2 };

        // Write new compound head
        let pg = Page::Allocated( AllocatedInfo { order : order + 1 } );
        self.write_page_info(pfn, pg);

        // Write compound pages
        for i in 1..nr_pages {
            let pg = Page::CompoundPage( CompoundInfo { order : order + 1 } );
            self.write_page_info(pfn + i, pg);
        }

        // Do the accounting - none of the pages is free yet, so free_pages is
        // not updated here.
        self.nr_pages[order]     -= 2;
        self.nr_pages[order + 1] += 1;

        Ok(pfn)
    }

    fn next_free_pfn(&self, pfn : usize, order : usize) -> usize {
        let page = self.read_page_info(pfn);
        match page {
            Page::Free(fi)  => fi.next_page,
            _               => { panic!("Unexpected page type in free-list for order {}", order); }
        }
    }


    fn allocate_pfn(&mut self, pfn : usize, order : usize) -> Result<(), ()> {
        let first_pfn = self.next_page[order];

        // Handle special cases first
        if first_pfn == 0 {
            // No pages for that order
            return Err(());
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
                let pg = Page::Free( FreeInfo { next_page : next_pfn, order : order } );
                self.write_page_info(old_pfn, pg);

                let pg = Page::Allocated( AllocatedInfo { order : order } );
                self.write_page_info(current_pfn, pg);

				self.free_pages[order] -= 1;

                return Ok(());
            }

            old_pfn = current_pfn;
        }

        return Err(());
    }

    fn free_page_raw(&mut self, pfn : usize, order : usize) {
        let old_next = self.next_page[order];
        let pg = Page::Free( FreeInfo { next_page : old_next, order : order } );

        self.write_page_info(pfn, pg);
        self.next_page[order] = pfn;

        self.free_pages[order] += 1;
    }

    fn try_to_merge_page(&mut self, pfn : usize, order : usize) -> Result<usize, ()> {
        let neighbor_pfn = self.compound_neighbor(pfn, order)?;
        let neighbor_page = self.read_page_info(neighbor_pfn);

        if let Page::Free(fi) = neighbor_page {
            if fi.order != order {
                return Err(());
            }

            self.allocate_pfn(neighbor_pfn, order)?;

            let new_pfn = self.merge_pages(pfn, neighbor_pfn, order)?;

            Ok(new_pfn)
        } else {
            Err(())
        }
    }

    fn free_page_order(&mut self, pfn : usize, order : usize) {
        match self.try_to_merge_page(pfn, order) {
            Err(_e)     => { self.free_page_raw(pfn, order); },
            Ok(new_pfn) => { self.free_page_order(new_pfn, order + 1); }
        }
    }

    pub fn free_page(&mut self, vaddr : VirtAddr) {
        let res = self.get_page_info(vaddr);

        if let Err(_e) = res {
            return;
        }

        let pfn = (vaddr - self.start_virt) / PAGE_SIZE;

        match res.unwrap() {
            Page::Allocated(ai)  => { self.free_page_order(pfn, ai.order); },
            Page::SlabPage(_si)  => { self.free_page_order(pfn, 0); },
            _ => { panic!("Unexpected page type in MemoryRegion::free_page()"); }
        }
    }

    pub fn memory_info(&self) -> MemInfo {
        MemInfo {
            total_pages : self.nr_pages,
            free_pages  : self.free_pages,
        }
    }
    
    pub fn init_memory(&mut self) {
        let size = size_of::<PageStorageType>();
        let meta_pages = align_up((self.page_count * size) as usize, PAGE_SIZE) / PAGE_SIZE;

        /* Mark page storage as reserved */
        for i in 0..meta_pages {
            let pg : Page = Page::Reserved( ReservedInfo { } );
            self.write_page_info(i, pg);
        }

        self.nr_pages[0]   = self.page_count - meta_pages;

        /* Mark all pages as allocated */
        for i in meta_pages..self.page_count {
            let pg = Page::Allocated( AllocatedInfo { order : 0 } );
            self.write_page_info(i, pg);
        }

        /* Now free all pages */
        for i in meta_pages..self.page_count {
            self.free_page_order(i, 0);
        }
    }
}

pub fn print_memory_info(info : &MemInfo) {
    let mut pages_4k        = 0;
    let mut free_pages_4k   = 0;

    for i in 0..MAX_ORDER {
        let nr_4k_pages : usize = 1 << i;
        println!("Order-{:#02}: total pages: {:#5} free pages: {:#5}", i, info.total_pages[i], info.free_pages[i]);
        pages_4k        += info.total_pages[i]  * nr_4k_pages;
        free_pages_4k   += info.free_pages[i]   * nr_4k_pages;
    }

    println!("Total memory: {}KiB free memory: {}KiB", (pages_4k * PAGE_SIZE) / 1024, (free_pages_4k * PAGE_SIZE) / 1024);
}

static ROOT_MEM : SpinLock<MemoryRegion> = SpinLock::new(MemoryRegion::new());

pub fn allocate_page() -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_page()
}

pub fn allocate_pages(order : usize) -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_pages(order)
}

pub fn allocate_slab_page(slab : Option<VirtAddr>) -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_slab_page(slab)
}

pub fn allocate_zeroed_page() -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_zeroed_page()
}

pub fn free_page(vaddr : VirtAddr) {
    ROOT_MEM.lock().free_page(vaddr)
}

pub fn virt_to_phys(vaddr : VirtAddr) -> PhysAddr {
    match ROOT_MEM.lock().virt_to_phys(vaddr) {
        None => { panic!("Invalid virtual address {:#018x}", vaddr); },
        Some(v) => v,
    }
}

pub fn phys_to_virt(paddr : PhysAddr) -> VirtAddr {
    match ROOT_MEM.lock().phys_to_virt(paddr) {
        None => { panic!("Invalid physical address {:#018x}", paddr); },
        Some(p) => p,
    }
}

pub fn memory_info() -> MemInfo {
    ROOT_MEM.lock().memory_info()
}

struct SlabPage {
    vaddr       : VirtAddr,
    capacity    : u16,
    free        : u16,
    item_size   : u16,
    used_bitmap : [u64; 2],
    next_page   : VirtAddr,
}

impl SlabPage {
    pub const fn new() -> Self {
        SlabPage {
            vaddr       : 0,
            capacity    : 0,
            free        : 0,
            item_size   : 0,
            used_bitmap : [0; 2],
            next_page   : 0,
        }
    }

    pub fn init(&mut self, slab_vaddr : Option<VirtAddr>, mut item_size : u16) -> Result<(), ()> {
        if self.item_size != 0 {
            return Ok(());
        }

        assert!(item_size <= (PAGE_SIZE / 2) as u16);
        assert!(self.vaddr == 0);

        if item_size < 32 {
            item_size = 32;
        }

        if let Ok(vaddr) = allocate_slab_page(slab_vaddr) {
            self.vaddr      = vaddr;
            self.item_size      = item_size;
            self.capacity       = (PAGE_SIZE as u16) / item_size;
            self.free           = self.capacity;
        } else {
            return Err(());
        }

        Ok(())
    }

    pub fn destroy(&mut self) {
        if self.vaddr == 0 {
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

    pub fn set_next_page(&mut self, next_page : VirtAddr) {
        self.next_page = next_page;
    }

    pub fn allocate(&mut self) -> Result<VirtAddr, ()> {
        if self.free == 0 {
            return Err(())
        }

        for i in 0..self.capacity {
            let idx  = (i / 64) as usize;
            let mask = 1u64 << (i % 64);

            if self.used_bitmap[idx] & mask == 0 {
                self.used_bitmap[idx] |= mask;
                self.free -= 1;
                let offset = (self.item_size * i) as VirtAddr;
                return Ok(self.vaddr + offset);
            }
        }

        Err(())
    }

    pub fn free(&mut self, vaddr : VirtAddr) -> Result<(), ()> {
        if vaddr < self.vaddr || vaddr >= self.vaddr + PAGE_SIZE {
            return Err(());
        }

        assert!(self.item_size > 0);

        let item_size = self.item_size as VirtAddr;
        let offset = vaddr - self.vaddr;
        let i = offset / item_size;
        let idx = (i / 64) as usize;
        let mask = 1u64 << (i % 64);

        self.used_bitmap[idx] &= !mask;
        self.free += 1;

        Ok(())
    }
}

#[repr(align(16))]
struct SlabCommon {
    item_size  : u16,
    capacity   : u32,
    free       : u32,
    pages      : u32,
    full_pages : u32,
    free_pages : u32,
    page       : SlabPage,
}

impl SlabCommon {
    const fn new(item_size : u16) -> Self {
        SlabCommon {
            item_size  : item_size,
            capacity   : 0,
            free       : 0,
            pages      : 0,
            full_pages : 0,
            free_pages : 0,
            page       : SlabPage::new(),
        }
    }

    fn init(&mut self, slab_vaddr : Option<VirtAddr>) -> Result<(), ()> {
        if let Err(_e) = self.page.init(slab_vaddr, self.item_size) {
            return Err(());
        }

        self.capacity   = self.page.get_capacity() as u32;
        self.free   = self.capacity;
        self.pages  = 1;
        self.full_pages = 0;
        self.free_pages = 1;

        Ok(())
    }

    fn add_slab_page(&mut self, new_page : &mut SlabPage) {
        let old_next_page = self.page.get_next_page();
        new_page.set_next_page(old_next_page);
        self.page.set_next_page((new_page as *mut SlabPage) as VirtAddr);

        let capacity = new_page.get_capacity() as u32;
        self.pages      += 1;
        self.free_pages += 1;
        self.capacity   += capacity;
        self.free       += capacity;
    }

    fn remove_slab_page(&mut self, prev_page : &mut SlabPage, old_page : &SlabPage) {
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
        let mut page =  &mut self.page as *mut SlabPage;
        unsafe { loop {
            let free = (*page).get_free();

            if let Ok(vaddr) = (*page).allocate() {
                let capacity = (*page).get_capacity();
                self.free -= 1;

                if free == capacity {
                    self.free_pages -= 1;
                } else if free == 1 {
                    self.full_pages += 1;
                }

                return vaddr;
            }

            let next_page = (*page).get_next_page();
            assert_ne!(next_page, 0); // Cannot happen with free slots on entry.
            page = next_page as *mut SlabPage;
        } }
    }

    fn deallocate_slot(&mut self, vaddr : VirtAddr) {
        let mut page =  &mut self.page as *mut SlabPage;
        unsafe { loop {
            let free = (*page).get_free();

            if let Ok(_o) = (*page).free(vaddr) {
                let capacity = (*page).get_capacity();
                self.free += 1;

                if free == 0 {
                    self.full_pages -= 1;
                } else if free + 1 == capacity {
                    self. free_pages += 1;
                }

                return;
            }

            let next_page = (*page).get_next_page();
            assert_ne!(next_page, 0); // Object does not belong to this Slab.
            page = next_page as *mut SlabPage;
        } }
    }
}

struct SlabPageSlab {
    common : SlabCommon,
}

impl SlabPageSlab {
    const fn new() -> Self {
        SlabPageSlab {
            common : SlabCommon::new(size_of::<SlabPage>() as u16),
        }
    }

    fn init(&mut self) -> Result<(), ()> {
        self.common.init(Option::None)
    }

    fn grow_slab(&mut self) -> Result<(), ()> {
        if self.common.capacity == 0 {
            if let Err(_e) = self.init() {
                return Err(());
            }
            return Ok(());
        }

        // Make sure there's always at least one SlabPage slot left for extending the SlabPageSlab itself.
        if self.common.free >= 2 {
            return Ok(())
        }
        assert_ne!(self.common.free, 0);

        let page_vaddr = self.common.allocate_slot();
        let slab_page = unsafe {&mut *(page_vaddr as *mut SlabPage)};

        *slab_page = SlabPage::new();
        if let Err(_e) = slab_page.init(Option::None, self.common.item_size) {
            self.common.deallocate_slot(page_vaddr);
            return Err(());
        }

        self.common.add_slab_page(slab_page);

        Ok(())
    }

    fn shrink_slab(&mut self) {
        // The SlabPageSlab uses SlabPages on its own and freeing a SlabPage can empty another SlabPage.
        while self.common.free_pages > 1 {
            let mut last_page =  &mut self.common.page as *mut SlabPage;
            let mut next_page_vaddr = self.common.page.get_next_page();
            let mut freed_one = false;
            loop {
                if next_page_vaddr == 0 {
                    break;
                }
                let slab_page = unsafe {&mut *(next_page_vaddr as *mut SlabPage)};
                next_page_vaddr = slab_page.get_next_page();

                let capacity = slab_page.get_capacity();
                let free     = slab_page.get_free();
                if free == capacity {
                    self.common.remove_slab_page(unsafe {&mut *last_page}, slab_page);
                    slab_page.destroy();
                    self.common.deallocate_slot(slab_page as *mut SlabPage as VirtAddr);
                    freed_one = true;
                } else {
                    last_page = slab_page;
                }
            }
            assert_eq!(freed_one, true);
        }
    }

    fn allocate(&mut self) -> Result<*mut SlabPage, ()> {
        if let Err(_) = self.grow_slab() {
            return Err(());
        }

        return Ok(unsafe{&mut *(self.common.allocate_slot() as *mut SlabPage)});
    }

    fn deallocate(&mut self, slab_page : *mut SlabPage) {
        self.common.deallocate_slot(slab_page as VirtAddr);
        self.shrink_slab();
    }
}

struct Slab {
    common : SlabCommon,
}

impl Slab {
    const fn new(item_size : u16) -> Self {
        Slab {
            common : SlabCommon::new(item_size),
        }
    }

    fn init(&mut self) -> Result<(), ()> {
        let slab_vaddr = (self as *mut Slab) as VirtAddr;
        self.common.init(Option::Some(slab_vaddr))
    }

    fn grow_slab(&mut self) -> Result<(), ()> {
        if self.common.capacity == 0 {
            if let Err(_e) = self.init() {
                return Err(());
            }
            return Ok(());
        }

        let slab_page =
            match SLAB_PAGE_SLAB.lock().allocate() {
                Ok(slab_page) => unsafe {&mut *slab_page},
                Err(_) => return Err(()),
            };
        let slab_vaddr = (self as *mut Slab) as VirtAddr;
        *slab_page = SlabPage::new();
        if let Err(_e) = slab_page.init(Option::Some(slab_vaddr), self.common.item_size) {
            SLAB_PAGE_SLAB.lock().deallocate(slab_page);
            return Err(())
        }

        self.common.add_slab_page(&mut *slab_page);
        Ok(())
    }

    unsafe fn shrink_slab(&mut self) {
        let mut last_page =  &mut self.common.page as *mut SlabPage;
        let mut page_vaddr = self.common.page.get_next_page();

        loop {
            if page_vaddr == 0 {
                break;
            }

            let slab_page = page_vaddr as *mut SlabPage;
            let capacity = (*slab_page).get_capacity();
            let free     = (*slab_page).get_free();

            if free == capacity {
                self.common.remove_slab_page(&mut *last_page, &mut *slab_page);
                (*slab_page).destroy();
                SLAB_PAGE_SLAB.lock().deallocate(slab_page);
                return;
            }

            last_page = slab_page;
            page_vaddr = (*slab_page).get_next_page();
        }
    }

    fn adjust_slab_size(&mut self) -> Result<(), ()> {
        if self.common.capacity == 0 {
            return self.grow_slab();
        }

        let free : u64 = ((self.common.free as u64) * 100) / (self.common.capacity as u64);

        if free < 25 && self.common.free_pages < 2 {
            return self.grow_slab();
        } else if self.common.free_pages > 1 && free >= 50 {
            unsafe { self.shrink_slab(); }
        }

        Ok(())
    }

    fn allocate(&mut self) -> Result<VirtAddr, ()> {
        if let Err(_e) = self.adjust_slab_size() {
            return Err(());
        }

        return Ok(self.common.allocate_slot());
    }

    fn deallocate(&mut self, vaddr : VirtAddr) {
        self.common.deallocate_slot(vaddr);
        self.adjust_slab_size().expect("Failed to adjust slab size in deallocation path");
    }
}

static SLAB_PAGE_SLAB : SpinLock<SlabPageSlab> = SpinLock::new(SlabPageSlab::new());

pub struct SvsmAllocator {
    slab_size_32   : SpinLock<Slab>,
    slab_size_64   : SpinLock<Slab>,
    slab_size_128  : SpinLock<Slab>,
    slab_size_256  : SpinLock<Slab>,
    slab_size_512  : SpinLock<Slab>,
    slab_size_1024 : SpinLock<Slab>,
    slab_size_2048 : SpinLock<Slab>,
}

impl SvsmAllocator {
    pub const fn new() -> Self {
        SvsmAllocator {
            slab_size_32   : SpinLock::new(Slab::new(32)),
            slab_size_64   : SpinLock::new(Slab::new(64)),
            slab_size_128  : SpinLock::new(Slab::new(128)),
            slab_size_256  : SpinLock::new(Slab::new(256)),
            slab_size_512  : SpinLock::new(Slab::new(512)),
            slab_size_1024 : SpinLock::new(Slab::new(1024)),
            slab_size_2048 : SpinLock::new(Slab::new(2048)),
        }
    }

    fn get_order(size : usize) -> usize {
        let mut val = (size - 1) >> PAGE_SHIFT;
        let mut order : usize = 0;

        loop {
            if val == 0 {
                break;
            }

            order += 1;
            val  >>= 1;
        }

        order
    }
}

unsafe impl GlobalAlloc for SvsmAllocator {

    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret : Result<VirtAddr, ()>;
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
            let order = SvsmAllocator::get_order(size);
            if order >= MAX_ORDER {
                return ptr::null_mut();
            }
            ret = allocate_pages(order);
        }

        if let Err(_e) = ret {
            return ptr::null_mut();
        }

        ret.unwrap() as *mut u8
    }

    unsafe fn dealloc(&self, ptr : *mut u8, _layout : Layout) {
        let virt_addr = ptr as VirtAddr;

        let result = ROOT_MEM.lock().get_page_info(virt_addr);

        if let Err(_e) = result {
            panic!("Freeing unknown memory");
        }

        let info = result.unwrap();

        match info {
            Page::Allocated(_ai) => { free_page(virt_addr); },
            Page::SlabPage(si) => {
                assert_ne!(si.slab, 0);
                let slab = si.slab  as *mut Slab;

                (*slab).deallocate(virt_addr);
            },
            _ => { panic!("Freeing memory on unsupported page type"); }
        }
    }
}

#[global_allocator]
pub static mut ALLOCATOR : SvsmAllocator = SvsmAllocator::new();

pub fn root_mem_init(pstart : PhysAddr, vstart : VirtAddr, page_count : usize) {
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

use crate::println;

pub fn print_alloc_info() {
    for i in 0..MAX_ORDER {
        let nr_pages   = ROOT_MEM.lock().nr_pages[i];
        let free_pages = ROOT_MEM.lock().free_pages[i];
        println!("Order-{}: Pages: {:#04} Free Pages: {:#04}", i, nr_pages, free_pages);
    }
}

pub fn memory_init(launch_info : &KernelLaunchInfo) {
    let mem_size    = launch_info.kernel_end - launch_info.kernel_start;
    let vstart      = unsafe { (&heap_start as *const u8) as VirtAddr };
    let vend        = (launch_info.virt_base + mem_size) as VirtAddr;
    let page_count  = (vend - vstart) / PAGE_SIZE;
    let heap_offset = vstart - launch_info.virt_base as VirtAddr;
    let pstart      = launch_info.kernel_start as PhysAddr + heap_offset;

    root_mem_init(pstart, vstart, page_count);
}
