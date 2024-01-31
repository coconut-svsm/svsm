// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::write_cr3;
use crate::cpu::cpuid::cpuid_table;
use crate::cpu::features::{cpu_has_nx, cpu_has_pge};
use crate::cpu::flush_tlb_global_sync;
use crate::error::SvsmError;
use crate::locking::{LockGuard, SpinLock};
use crate::mm::alloc::{allocate_zeroed_page, free_page};
use crate::mm::{phys_to_virt, virt_to_phys, PGTABLE_LVL3_IDX_SHARED};
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;
use bitflags::bitflags;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::{cmp, ptr};

extern crate alloc;
use alloc::boxed::Box;

const ENTRY_COUNT: usize = 512;
static ENCRYPT_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::new(0);
static MAX_PHYS_ADDR: ImmutAfterInitCell<u64> = ImmutAfterInitCell::uninit();
pub const LAUNCH_VMSA_ADDR: PhysAddr = PhysAddr::new(0xFFFFFFFFF000);
static FEATURE_MASK: ImmutAfterInitCell<PTEntryFlags> =
    ImmutAfterInitCell::new(PTEntryFlags::empty());

pub fn paging_init_early() {
    init_encrypt_mask();

    let mut feature_mask = PTEntryFlags::all();
    feature_mask.remove(PTEntryFlags::NX);
    feature_mask.remove(PTEntryFlags::GLOBAL);
    FEATURE_MASK.reinit(&feature_mask);
}

pub fn paging_init() {
    init_encrypt_mask();

    let mut feature_mask = PTEntryFlags::all();
    if !cpu_has_nx() {
        feature_mask.remove(PTEntryFlags::NX);
    }
    if !cpu_has_pge() {
        feature_mask.remove(PTEntryFlags::GLOBAL);
    }
    FEATURE_MASK.reinit(&feature_mask);
}

fn init_encrypt_mask() {
    // Find C bit position
    let res = cpuid_table(0x8000001f).expect("Can not get C-Bit position from CPUID table");
    let c_bit = res.ebx & 0x3f;
    let mask = 1u64 << c_bit;
    ENCRYPT_MASK.reinit(&(mask as usize));

    // Find physical address size.
    let res = cpuid_table(0x80000008).expect("Can not get physical address size from CPUID table");
    let guest_phys_addr_size = (res.eax >> 16) & 0xff;
    let host_phys_addr_size = res.eax & 0xff;
    let phys_addr_size = if guest_phys_addr_size == 0 {
        // When [GuestPhysAddrSize] is zero, refer to the PhysAddrSize field
        // for the maximum guest physical address size.
        // - APM3, E.4.7 Function 8000_0008h - Processor Capacity Parameters and Extended Feature Identification
        host_phys_addr_size
    } else {
        guest_phys_addr_size
    };

    // If the C-bit is a physical address bit however, the guest physical
    // address space is effectively reduced by 1 bit.
    // - APM2, 15.34.6 Page Table Support
    let effective_phys_addr_size = cmp::min(c_bit, phys_addr_size);

    let max_addr = 1 << effective_phys_addr_size;
    MAX_PHYS_ADDR.reinit(&max_addr);
}

fn encrypt_mask() -> usize {
    *ENCRYPT_MASK
}

/// Returns the exclusive end of the physical address space.
pub fn max_phys_addr() -> PhysAddr {
    PhysAddr::from(*MAX_PHYS_ADDR)
}

fn supported_flags(flags: PTEntryFlags) -> PTEntryFlags {
    flags & *FEATURE_MASK
}

fn strip_c_bit(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() & !encrypt_mask())
}

fn set_c_bit(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() | encrypt_mask())
}

bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct PTEntryFlags: u64 {
        const PRESENT       = 1 << 0;
        const WRITABLE      = 1 << 1;
        const USER      = 1 << 2;
        const ACCESSED      = 1 << 5;
        const DIRTY     = 1 << 6;
        const HUGE      = 1 << 7;
        const GLOBAL        = 1 << 8;
        const NX        = 1 << 63;
    }
}

impl PTEntryFlags {
    pub fn exec() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::ACCESSED | Self::DIRTY
    }

    pub fn data() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::WRITABLE | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn data_ro() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_exec() -> Self {
        Self::PRESENT | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data_ro() -> Self {
        Self::PRESENT | Self::NX | Self::ACCESSED | Self::DIRTY
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PTEntry(PhysAddr);

impl PTEntry {
    pub fn is_clear(&self) -> bool {
        self.0.is_null()
    }

    pub fn clear(&mut self) {
        self.0 = PhysAddr::null();
    }

    pub fn present(&self) -> bool {
        self.flags().contains(PTEntryFlags::PRESENT)
    }

    pub fn raw(&self) -> u64 {
        self.0.bits() as u64
    }

    pub fn flags(&self) -> PTEntryFlags {
        PTEntryFlags::from_bits_truncate(self.0.bits() as u64)
    }

    pub fn set(&mut self, addr: PhysAddr, flags: PTEntryFlags) {
        let addr = addr.bits() as u64;
        assert_eq!(addr & !0x000f_ffff_ffff_f000, 0);
        self.0 = PhysAddr::from(addr | supported_flags(flags).bits());
    }

    pub fn address(&self) -> PhysAddr {
        let addr = PhysAddr::from(self.0.bits() & 0x000f_ffff_ffff_f000);
        strip_c_bit(addr)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PTPage {
    entries: [PTEntry; ENTRY_COUNT],
}

impl Default for PTPage {
    fn default() -> Self {
        let entries = [PTEntry::default(); ENTRY_COUNT];
        PTPage { entries }
    }
}

impl Index<usize> for PTPage {
    type Output = PTEntry;

    fn index(&self, index: usize) -> &PTEntry {
        &self.entries[index]
    }
}

impl IndexMut<usize> for PTPage {
    fn index_mut(&mut self, index: usize) -> &mut PTEntry {
        &mut self.entries[index]
    }
}

#[derive(Debug)]
pub enum Mapping<'a> {
    Level3(&'a mut PTEntry),
    Level2(&'a mut PTEntry),
    Level1(&'a mut PTEntry),
    Level0(&'a mut PTEntry),
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct PageTable {
    root: PTPage,
}

impl PageTable {
    pub fn load(&self) {
        write_cr3(self.cr3_value());
    }

    pub fn cr3_value(&self) -> PhysAddr {
        let pgtable = VirtAddr::from(self as *const PageTable);
        let cr3 = virt_to_phys(pgtable);
        set_c_bit(cr3)
    }

    pub fn clone_shared(&self) -> Result<PageTableRef, SvsmError> {
        let root_ptr = PageTable::allocate_page_table()?;
        let pgtable = root_ptr.cast::<PageTable>();

        unsafe {
            let root = root_ptr.as_mut().unwrap();
            root.entries[PGTABLE_LVL3_IDX_SHARED] = self.root.entries[PGTABLE_LVL3_IDX_SHARED];
        }

        Ok(PageTableRef {
            pgtable_ptr: pgtable,
        })
    }

    pub fn copy_entry(&mut self, other: &PageTable, entry: usize) {
        self.root.entries[entry] = other.root.entries[entry];
    }

    fn allocate_page_table() -> Result<*mut PTPage, SvsmError> {
        let ptr = allocate_zeroed_page()?;
        Ok(ptr.as_mut_ptr::<PTPage>())
    }

    pub fn index<const L: usize>(vaddr: VirtAddr) -> usize {
        vaddr.bits() >> (12 + L * 9) & 0x1ff
    }

    fn entry_to_pagetable(entry: PTEntry) -> Option<&'static mut PTPage> {
        let flags = entry.flags();
        if !flags.contains(PTEntryFlags::PRESENT) || flags.contains(PTEntryFlags::HUGE) {
            return None;
        }

        let address = phys_to_virt(entry.address());
        Some(unsafe { &mut *address.as_mut_ptr::<PTPage>() })
    }

    fn walk_addr_lvl0(page: &mut PTPage, vaddr: VirtAddr) -> Mapping {
        let idx = PageTable::index::<0>(vaddr);

        Mapping::Level0(&mut page[idx])
    }

    fn walk_addr_lvl1(page: &mut PTPage, vaddr: VirtAddr) -> Mapping {
        let idx = PageTable::index::<1>(vaddr);
        let entry = page[idx];
        let ret = PageTable::entry_to_pagetable(entry);

        return match ret {
            Some(page) => PageTable::walk_addr_lvl0(page, vaddr),
            None => Mapping::Level1(&mut page[idx]),
        };
    }

    fn walk_addr_lvl2(page: &mut PTPage, vaddr: VirtAddr) -> Mapping {
        let idx = PageTable::index::<2>(vaddr);
        let entry = page[idx];
        let ret = PageTable::entry_to_pagetable(entry);

        return match ret {
            Some(page) => PageTable::walk_addr_lvl1(page, vaddr),
            None => Mapping::Level2(&mut page[idx]),
        };
    }

    fn walk_addr_lvl3(page: &mut PTPage, vaddr: VirtAddr) -> Mapping {
        let idx = PageTable::index::<3>(vaddr);
        let entry = page[idx];
        let ret = PageTable::entry_to_pagetable(entry);

        return match ret {
            Some(page) => PageTable::walk_addr_lvl2(page, vaddr),
            None => Mapping::Level3(&mut page[idx]),
        };
    }

    pub fn walk_addr(&mut self, vaddr: VirtAddr) -> Mapping {
        PageTable::walk_addr_lvl3(&mut self.root, vaddr)
    }

    fn alloc_pte_lvl3(entry: &mut PTEntry, vaddr: VirtAddr, size: PageSize) -> Mapping {
        let flags = entry.flags();

        if flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level3(entry);
        }

        let page = match PageTable::allocate_page_table() {
            Ok(page) => page,
            _ => return Mapping::Level3(entry),
        };

        let paddr = virt_to_phys(VirtAddr::from(page));
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.set(set_c_bit(paddr), flags);

        let idx = PageTable::index::<2>(vaddr);

        unsafe { PageTable::alloc_pte_lvl2(&mut (*page)[idx], vaddr, size) }
    }

    fn alloc_pte_lvl2(entry: &mut PTEntry, vaddr: VirtAddr, size: PageSize) -> Mapping {
        let flags = entry.flags();

        if flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level2(entry);
        }

        let page = match PageTable::allocate_page_table() {
            Ok(page) => page,
            _ => return Mapping::Level2(entry),
        };

        let paddr = virt_to_phys(VirtAddr::from(page));
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.set(set_c_bit(paddr), flags);

        let idx = PageTable::index::<1>(vaddr);

        unsafe { PageTable::alloc_pte_lvl1(&mut (*page)[idx], vaddr, size) }
    }

    fn alloc_pte_lvl1(entry: &mut PTEntry, vaddr: VirtAddr, size: PageSize) -> Mapping {
        let flags = entry.flags();

        if size == PageSize::Huge || flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level1(entry);
        }

        let page = match PageTable::allocate_page_table() {
            Ok(page) => page,
            _ => return Mapping::Level1(entry),
        };

        let paddr = virt_to_phys(VirtAddr::from(page));
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.set(set_c_bit(paddr), flags);

        let idx = PageTable::index::<0>(vaddr);

        unsafe { Mapping::Level0(&mut (*page)[idx]) }
    }

    pub fn alloc_pte_4k(&mut self, vaddr: VirtAddr) -> Mapping {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => PageTable::alloc_pte_lvl1(entry, vaddr, PageSize::Regular),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PageSize::Regular),
            Mapping::Level3(entry) => PageTable::alloc_pte_lvl3(entry, vaddr, PageSize::Regular),
        }
    }

    pub fn alloc_pte_2m(&mut self, vaddr: VirtAddr) -> Mapping {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => Mapping::Level1(entry),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PageSize::Huge),
            Mapping::Level3(entry) => PageTable::alloc_pte_lvl3(entry, vaddr, PageSize::Huge),
        }
    }

    fn do_split_4k(entry: &mut PTEntry) -> Result<(), SvsmError> {
        let page = PageTable::allocate_page_table()?;
        let mut flags = entry.flags();

        assert!(flags.contains(PTEntryFlags::HUGE));

        let addr_2m = PhysAddr::from(entry.address().bits() & 0x000f_ffff_fff0_0000);

        flags.remove(PTEntryFlags::HUGE);

        // Prepare PTE leaf page
        for i in 0..512 {
            let addr_4k = addr_2m + (i * PAGE_SIZE);
            unsafe {
                (*page).entries[i].clear();
                (*page).entries[i].set(set_c_bit(addr_4k), flags);
            }
        }

        entry.set(set_c_bit(virt_to_phys(VirtAddr::from(page))), flags);

        flush_tlb_global_sync();

        Ok(())
    }

    pub fn split_4k(mapping: Mapping) -> Result<(), SvsmError> {
        match mapping {
            Mapping::Level0(_entry) => Ok(()),
            Mapping::Level1(entry) => PageTable::do_split_4k(entry),
            Mapping::Level2(_entry) => Err(SvsmError::Mem),
            Mapping::Level3(_entry) => Err(SvsmError::Mem),
        }
    }

    fn clear_c_bit(entry: &mut PTEntry) {
        let flags = entry.flags();
        let addr = entry.address();

        // entry.address() returned with c-bit clear already
        entry.set(addr, flags);
    }

    fn set_c_bit(entry: &mut PTEntry) {
        let flags = entry.flags();
        let addr = entry.address();

        // entry.address() returned with c-bit clear already
        entry.set(set_c_bit(addr), flags);
    }

    pub fn set_shared_4k(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let mapping = self.walk_addr(vaddr);
        PageTable::split_4k(mapping)?;

        if let Mapping::Level0(entry) = self.walk_addr(vaddr) {
            PageTable::clear_c_bit(entry);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    pub fn set_encrypted_4k(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let mapping = self.walk_addr(vaddr);
        PageTable::split_4k(mapping)?;

        if let Mapping::Level0(entry) = self.walk_addr(vaddr) {
            PageTable::set_c_bit(entry);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    pub fn check_mapping(&mut self, vaddr: VirtAddr) -> Option<PhysAddr> {
        match self.walk_addr(vaddr) {
            Mapping::Level0(entry) => Some(entry.address()),
            Mapping::Level1(entry) => Some(entry.address()),
            _ => None,
        }
    }

    pub fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));
        assert!(paddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.alloc_pte_2m(vaddr);

        if let Mapping::Level1(entry) = mapping {
            entry.set(set_c_bit(paddr), flags | PTEntryFlags::HUGE);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    pub fn unmap_2m(&mut self, vaddr: VirtAddr) {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(_) => unreachable!(),
            Mapping::Level1(entry) => entry.clear(),
            Mapping::Level2(entry) => assert!(!entry.present()),
            Mapping::Level3(entry) => assert!(!entry.present()),
        }
    }

    pub fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        let mapping = self.alloc_pte_4k(vaddr);

        if let Mapping::Level0(entry) = mapping {
            entry.set(set_c_bit(paddr), flags);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    pub fn unmap_4k(&mut self, vaddr: VirtAddr) {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => entry.clear(),
            Mapping::Level1(entry) => assert!(!entry.present()),
            Mapping::Level2(entry) => assert!(!entry.present()),
            Mapping::Level3(entry) => assert!(!entry.present()),
        }
    }

    pub fn phys_addr(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, SvsmError> {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => {
                let offset = vaddr.page_offset();
                if !entry.flags().contains(PTEntryFlags::PRESENT) {
                    return Err(SvsmError::Mem);
                }
                Ok(entry.address() + offset)
            }
            Mapping::Level1(entry) => {
                let offset = vaddr.bits() & (PAGE_SIZE_2M - 1);
                if !entry.flags().contains(PTEntryFlags::PRESENT)
                    || !entry.flags().contains(PTEntryFlags::HUGE)
                {
                    return Err(SvsmError::Mem);
                }

                Ok(entry.address() + offset)
            }
            Mapping::Level2(_entry) => Err(SvsmError::Mem),
            Mapping::Level3(_entry) => Err(SvsmError::Mem),
        }
    }

    pub fn map_region_4k(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        for addr in vregion.iter_pages(PageSize::Regular) {
            let offset = addr - vregion.start();
            self.map_4k(addr, phys + offset, flags)?;
        }
        Ok(())
    }

    pub fn unmap_region_4k(&mut self, vregion: MemoryRegion<VirtAddr>) {
        for addr in vregion.iter_pages(PageSize::Regular) {
            self.unmap_4k(addr);
        }
    }

    pub fn map_region_2m(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        for addr in vregion.iter_pages(PageSize::Huge) {
            let offset = addr - vregion.start();
            self.map_2m(addr, phys + offset, flags)?;
        }
        Ok(())
    }

    pub fn unmap_region_2m(&mut self, vregion: MemoryRegion<VirtAddr>) {
        for addr in vregion.iter_pages(PageSize::Huge) {
            self.unmap_2m(addr);
        }
    }

    pub fn map_region(
        &mut self,
        region: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        let mut vaddr = region.start();
        let end = region.end();
        let mut paddr = phys;

        while vaddr < end {
            if vaddr.is_aligned(PAGE_SIZE_2M)
                && paddr.is_aligned(PAGE_SIZE_2M)
                && vaddr + PAGE_SIZE_2M <= end
                && self.map_2m(vaddr, paddr, flags).is_ok()
            {
                vaddr = vaddr + PAGE_SIZE_2M;
                paddr = paddr + PAGE_SIZE_2M;
                continue;
            }

            self.map_4k(vaddr, paddr, flags)?;
            vaddr = vaddr + PAGE_SIZE;
            paddr = paddr + PAGE_SIZE;
        }

        Ok(())
    }

    pub fn unmap_region(&mut self, vregion: MemoryRegion<VirtAddr>) {
        let mut vaddr = vregion.start();
        let end = vregion.end();

        while vaddr < end {
            let mapping = self.walk_addr(vaddr);

            match mapping {
                Mapping::Level0(entry) => {
                    entry.clear();
                    vaddr = vaddr + PAGE_SIZE;
                }
                Mapping::Level1(entry) => {
                    entry.clear();
                    vaddr = vaddr + PAGE_SIZE_2M;
                }
                _ => {
                    log::error!("Can't unmap - address not mapped {:#x}", vaddr);
                }
            }
        }
    }

    pub fn populate_pgtbl_part(&mut self, part: &PageTablePart) {
        let idx = part.index();
        let paddr = part.address();
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        let entry = &mut self.root[idx];
        entry.set(set_c_bit(paddr), flags);
    }
}

static INIT_PGTABLE: SpinLock<PageTableRef> = SpinLock::new(PageTableRef::unset());

pub fn set_init_pgtable(pgtable: PageTableRef) {
    let mut init_pgtable = INIT_PGTABLE.lock();
    assert!(!init_pgtable.is_set());
    *init_pgtable = pgtable;
}

pub fn get_init_pgtable_locked<'a>() -> LockGuard<'a, PageTableRef> {
    INIT_PGTABLE.lock()
}

#[derive(Debug)]
pub struct PageTableRef {
    pgtable_ptr: *mut PageTable,
}

impl PageTableRef {
    pub fn new(pgtable: &mut PageTable) -> PageTableRef {
        PageTableRef {
            pgtable_ptr: pgtable as *mut PageTable,
        }
    }

    pub const fn unset() -> PageTableRef {
        PageTableRef {
            pgtable_ptr: ptr::null_mut(),
        }
    }

    fn is_set(&self) -> bool {
        !self.pgtable_ptr.is_null()
    }
}

impl Deref for PageTableRef {
    type Target = PageTable;

    fn deref(&self) -> &Self::Target {
        assert!(self.is_set());
        unsafe { &*self.pgtable_ptr }
    }
}

impl DerefMut for PageTableRef {
    fn deref_mut(&mut self) -> &mut Self::Target {
        assert!(self.is_set());
        unsafe { &mut *self.pgtable_ptr }
    }
}

/// SAFETY: `PageTableRef` is more or less equivalent to a mutable reference to
///         a PageTable and so if `&mut PageTable` implements `Send` so does
///         `PageTableRef`.
unsafe impl Send for PageTableRef where &'static mut PageTable: Send {}

/// Represents a sub-tree of a page-table which can be mapped at a top-level index
#[derive(Default, Debug)]
struct RawPageTablePart {
    page: PTPage,
}

impl RawPageTablePart {
    fn entry_to_page(entry: PTEntry) -> Option<&'static mut PTPage> {
        let flags = entry.flags();
        if !flags.contains(PTEntryFlags::PRESENT) || flags.contains(PTEntryFlags::HUGE) {
            return None;
        }

        let address = phys_to_virt(entry.address());
        Some(unsafe { &mut *address.as_mut_ptr::<PTPage>() })
    }

    fn free_lvl1(page: &PTPage) {
        for idx in 0..ENTRY_COUNT {
            let entry = page[idx];

            if RawPageTablePart::entry_to_page(entry).is_some() {
                free_page(phys_to_virt(entry.address()));
            }
        }
    }

    fn free_lvl2(page: &PTPage) {
        for idx in 0..ENTRY_COUNT {
            let entry = page[idx];

            if let Some(l1_page) = RawPageTablePart::entry_to_page(entry) {
                RawPageTablePart::free_lvl1(l1_page);
                free_page(phys_to_virt(entry.address()));
            }
        }
    }

    fn free(&self) {
        RawPageTablePart::free_lvl2(&self.page);
    }

    fn address(&self) -> PhysAddr {
        virt_to_phys(VirtAddr::from(self as *const RawPageTablePart))
    }

    fn walk_addr(&mut self, vaddr: VirtAddr) -> Mapping {
        PageTable::walk_addr_lvl2(&mut self.page, vaddr)
    }

    fn alloc_pte_4k(&mut self, vaddr: VirtAddr) -> Mapping {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => PageTable::alloc_pte_lvl1(entry, vaddr, PageSize::Regular),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PageSize::Regular),
            Mapping::Level3(_) => panic!("PT level 3 not possible in PageTablePart"),
        }
    }

    pub fn alloc_pte_2m(&mut self, vaddr: VirtAddr) -> Mapping {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => Mapping::Level1(entry),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PageSize::Huge),
            Mapping::Level3(entry) => PageTable::alloc_pte_lvl3(entry, vaddr, PageSize::Huge),
        }
    }

    fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        let mapping = self.alloc_pte_4k(vaddr);

        let addr = if !shared { set_c_bit(paddr) } else { paddr };

        if let Mapping::Level0(entry) = mapping {
            entry.set(addr, flags);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    fn unmap_4k(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => {
                let e = *entry;
                entry.clear();
                Some(e)
            }
            Mapping::Level1(entry) => {
                assert!(!entry.present());
                None
            }
            Mapping::Level2(entry) => {
                assert!(!entry.present());
                None
            }
            Mapping::Level3(entry) => {
                assert!(!entry.present());
                None
            }
        }
    }

    pub fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));
        assert!(paddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.alloc_pte_2m(vaddr);
        let addr = if !shared { set_c_bit(paddr) } else { paddr };

        if let Mapping::Level1(entry) = mapping {
            entry.set(addr, flags | PTEntryFlags::HUGE);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    pub fn unmap_2m(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(_) => None,
            Mapping::Level1(entry) => {
                entry.clear();
                Some(*entry)
            }
            Mapping::Level2(entry) => {
                assert!(!entry.present());
                None
            }
            Mapping::Level3(entry) => {
                assert!(!entry.present());
                None
            }
        }
    }
}

impl Drop for RawPageTablePart {
    fn drop(&mut self) {
        self.free();
    }
}

/// Sub-tree of a page table that can be populated at the top-level
/// used for virtual memory management
#[derive(Debug)]
pub struct PageTablePart {
    /// The root of the page-table sub-tree
    raw: Box<RawPageTablePart>,
    /// The top-level index this PageTablePart is populated at
    idx: usize,
}

impl PageTablePart {
    /// Create a new PageTablePart and allocate a root page for the page-table sub-tree.
    ///
    /// # Arguments
    ///
    /// - `start`: Virtual start address this PageTablePart maps
    ///
    /// # Returns
    ///
    /// A new instance of PageTablePart
    pub fn new(start: VirtAddr) -> Self {
        PageTablePart {
            raw: Box::<RawPageTablePart>::default(),
            idx: PageTable::index::<3>(start),
        }
    }

    /// Request PageTable index to populate this instance to
    ///
    /// # Returns
    ///
    /// Index of the top-level PageTable this sub-tree is populated to
    pub fn index(&self) -> usize {
        self.idx
    }

    /// Request physical base address of the page-table sub-tree. This is
    /// needed to populate the PageTablePart.
    ///
    /// # Returns
    ///
    /// Physical base address of the page-table sub-tree
    pub fn address(&self) -> PhysAddr {
        self.raw.address()
    }

    /// Map a 4KiB page in the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - Virtual address to create the mapping. Must be aligned to 4KiB.
    /// * `paddr` - Physical address to map. Must be aligned to 4KiB.
    /// * `flags` - PTEntryFlags used for the mapping
    /// * `shared` - Defines whether the page is mapped shared or private
    ///
    /// # Returns
    ///
    /// OK(()) on Success, Err(SvsmError::Mem) on error.
    ///
    /// This function can fail when there not enough memory to allocate pages for the mapping.
    ///
    /// # Panics
    ///
    /// This method panics when either `vaddr` or `paddr` are not aligned to 4KiB.
    pub fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.raw.map_4k(vaddr, paddr, flags, shared)
    }

    /// Unmaps a 4KiB page from the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - The virtual address to unmap. Must be aligned to 4KiB.
    ///
    /// # Returns
    ///
    /// Returns a copy of the PTEntry that mapped the virtual address, if any.
    ///
    /// # Panics
    ///
    /// This method panics when `vaddr` is not aligned to 4KiB.
    pub fn unmap_4k(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.raw.unmap_4k(vaddr)
    }

    /// Map a 2MiB page in the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - Virtual address to create the mapping. Must be aligned to 2MiB.
    /// * `paddr` - Physical address to map. Must be aligned to 2MiB.
    /// * `flags` - PTEntryFlags used for the mapping
    /// * `shared` - Defines whether the page is mapped shared or private
    ///
    /// # Returns
    ///
    /// OK(()) on Success, Err(SvsmError::Mem) on error.
    ///
    /// This function can fail when there not enough memory to allocate pages for the mapping.
    ///
    /// # Panics
    ///
    /// This method panics when either `vaddr` or `paddr` are not aligned to 2MiB.
    pub fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.raw.map_2m(vaddr, paddr, flags, shared)
    }

    /// Unmaps a 2MiB page from the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - The virtual address to unmap. Must be aligned to 2MiB.
    ///
    /// # Returns
    ///
    /// Returns a copy of the PTEntry that mapped the virtual address, if any.
    ///
    /// # Panics
    ///
    /// This method panics when `vaddr` is not aligned to 2MiB.
    pub fn unmap_2m(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.raw.unmap_2m(vaddr)
    }
}
