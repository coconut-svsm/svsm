// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::cpu::control_regs::write_cr3;
use crate::cpu::cpuid::cpuid_table;
use crate::cpu::features::{cpu_has_nx, cpu_has_pge};
use crate::cpu::flush_tlb_global_sync;
use crate::locking::{LockGuard, SpinLock};
use crate::mm::alloc::allocate_zeroed_page;
use crate::mm::{phys_to_virt, virt_to_phys, PGTABLE_LVL3_IDX_SHARED};
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::is_aligned;
use bitflags::bitflags;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::ptr;

const ENTRY_COUNT: usize = 512;
static ENCRYPT_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::new(0);
static FEATURE_MASK: ImmutAfterInitCell<PTEntryFlags> =
    ImmutAfterInitCell::new(PTEntryFlags::empty());

pub fn paging_init_early(encrypt_mask: u64) {
    unsafe { ENCRYPT_MASK.reinit(&(encrypt_mask as usize)) };

    let mut feature_mask = PTEntryFlags::all();
    feature_mask.remove(PTEntryFlags::NX);
    feature_mask.remove(PTEntryFlags::GLOBAL);
    unsafe { FEATURE_MASK.reinit(&feature_mask) };
}

pub fn paging_init() {
    // Find C bit position
    let res = cpuid_table(0x8000001f);

    if res.is_none() {
        panic!("Can not get C-Bit position from CPUID table");
    }

    let c_bit = res.unwrap().ebx & 0x3f;
    let new_encrypt_mask = 1usize << c_bit;
    let old_encrypt_mask = *ENCRYPT_MASK;
    if old_encrypt_mask != 0 && old_encrypt_mask != new_encrypt_mask {
        // The ENCRYPT_MASK has previously obtained by some other means,
        // e.g. through a GHCB MSR protocol info request, and is inconsistent
        // with what the more secure cpuid page says. Either the HV is buggy or
        // is trying to actively fool us.
        panic!("Early C-Bit position inconsistent with CPUID table");
    }

    unsafe { ENCRYPT_MASK.reinit(&new_encrypt_mask) };

    let mut feature_mask = PTEntryFlags::all();
    if !cpu_has_nx() {
        feature_mask.remove(PTEntryFlags::NX);
    }
    if !cpu_has_pge() {
        feature_mask.remove(PTEntryFlags::GLOBAL);
    }
    unsafe { FEATURE_MASK.reinit(&feature_mask) };
}

fn encrypt_mask() -> usize {
    *ENCRYPT_MASK
}

fn supported_flags(flags: PTEntryFlags) -> PTEntryFlags {
    flags & *FEATURE_MASK
}

fn strip_c_bit(paddr: PhysAddr) -> PhysAddr {
    paddr & !encrypt_mask()
}

fn set_c_bit(paddr: PhysAddr) -> PhysAddr {
    paddr | encrypt_mask()
}

bitflags! {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PTEntry(pub u64);

impl PTEntry {
    pub fn is_clear(&self) -> bool {
        self.0 == 0
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }

    pub fn present(&self) -> bool {
        self.flags().contains(PTEntryFlags::PRESENT)
    }

    pub fn raw(&self) -> u64 {
        self.0
    }

    pub fn flags(&self) -> PTEntryFlags {
        PTEntryFlags::from_bits_truncate(self.0)
    }

    pub fn set(&mut self, addr: PhysAddr, flags: PTEntryFlags) {
        assert_eq!(addr & !0x000f_ffff_ffff_f000, 0);
        self.0 = (addr as u64) | supported_flags(flags).bits();
    }

    pub fn address(&self) -> PhysAddr {
        strip_c_bit((self.0 & 0x000f_ffff_ffff_f000) as PhysAddr)
    }
}

#[repr(C)]
pub struct PTPage {
    entries: [PTEntry; ENTRY_COUNT],
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

pub enum Mapping<'a> {
    Level3(&'a mut PTEntry),
    Level2(&'a mut PTEntry),
    Level1(&'a mut PTEntry),
    Level0(&'a mut PTEntry),
}

#[repr(C)]
pub struct PageTable {
    root: PTPage,
}

impl PageTable {
    pub fn load(&self) {
        write_cr3(self.cr3_value());
    }

    pub fn cr3_value(&self) -> usize {
        let pgtable: usize = (self as *const PageTable) as usize;
        let cr3 = virt_to_phys(pgtable);
        set_c_bit(cr3)
    }

    pub fn clone_shared(&self) -> Result<PageTableRef, ()> {
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

    pub fn exec_flags() -> PTEntryFlags {
        PTEntryFlags::PRESENT | PTEntryFlags::GLOBAL | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }

    pub fn data_flags() -> PTEntryFlags {
        PTEntryFlags::PRESENT
            | PTEntryFlags::GLOBAL
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::NX
            | PTEntryFlags::ACCESSED
            | PTEntryFlags::DIRTY
    }

    pub fn data_ro_flags() -> PTEntryFlags {
        PTEntryFlags::PRESENT
            | PTEntryFlags::GLOBAL
            | PTEntryFlags::NX
            | PTEntryFlags::ACCESSED
            | PTEntryFlags::DIRTY
    }

    fn allocate_page_table() -> Result<*mut PTPage, ()> {
        let ptr = allocate_zeroed_page()?;
        Ok(ptr as *mut PTPage)
    }

    fn index<const L: usize>(vaddr: VirtAddr) -> usize {
        vaddr >> (12 + L * 9) & 0x1ff
    }

    fn entry_to_pagetable(entry: PTEntry) -> Option<&'static mut PTPage> {
        let flags = entry.flags();
        if !flags.contains(PTEntryFlags::PRESENT) || flags.contains(PTEntryFlags::HUGE) {
            return None;
        }

        let address = phys_to_virt(entry.address());
        Some(unsafe { &mut *(address as *mut PTPage) })
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

    fn alloc_pte_lvl3(entry: &mut PTEntry, vaddr: VirtAddr, pgsize: usize) -> Mapping {
        let flags = entry.flags();

        if flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level3(entry);
        }

        let page = match PageTable::allocate_page_table() {
            Ok(page) => page,
            _ => return Mapping::Level3(entry),
        };

        let paddr = virt_to_phys(page as VirtAddr);
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.clear();
        entry.set(set_c_bit(paddr), flags);

        let idx = PageTable::index::<2>(vaddr);

        unsafe { PageTable::alloc_pte_lvl2(&mut (*page)[idx], vaddr, pgsize) }
    }

    fn alloc_pte_lvl2(entry: &mut PTEntry, vaddr: VirtAddr, pgsize: usize) -> Mapping {
        let flags = entry.flags();

        if flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level2(entry);
        }

        let page = match PageTable::allocate_page_table() {
            Ok(page) => page,
            _ => return Mapping::Level2(entry),
        };

        let paddr = virt_to_phys(page as VirtAddr);
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.clear();
        entry.set(set_c_bit(paddr), flags);

        let idx = PageTable::index::<1>(vaddr);

        unsafe { PageTable::alloc_pte_lvl1(&mut (*page)[idx], vaddr, pgsize) }
    }

    fn alloc_pte_lvl1(entry: &mut PTEntry, vaddr: VirtAddr, pgsize: usize) -> Mapping {
        let flags = entry.flags();

        if pgsize == PAGE_SIZE_2M || flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level1(entry);
        }

        let page = match PageTable::allocate_page_table() {
            Ok(page) => page,
            _ => return Mapping::Level1(entry),
        };

        let paddr = virt_to_phys(page as VirtAddr);
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.clear();
        entry.set(set_c_bit(paddr), flags);

        let idx = PageTable::index::<0>(vaddr);

        unsafe { Mapping::Level0(&mut (*page)[idx]) }
    }

    pub fn alloc_pte_4k(&mut self, vaddr: VirtAddr) -> Mapping {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => PageTable::alloc_pte_lvl1(entry, vaddr, PAGE_SIZE),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PAGE_SIZE),
            Mapping::Level3(entry) => PageTable::alloc_pte_lvl3(entry, vaddr, PAGE_SIZE),
        }
    }

    pub fn alloc_pte_2m(&mut self, vaddr: VirtAddr) -> Mapping {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => Mapping::Level1(entry),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PAGE_SIZE_2M),
            Mapping::Level3(entry) => PageTable::alloc_pte_lvl3(entry, vaddr, PAGE_SIZE_2M),
        }
    }

    fn do_split_4k(entry: &mut PTEntry) -> Result<(), ()> {
        let page = PageTable::allocate_page_table()?;
        let mut flags = entry.flags();

        assert!(flags.contains(PTEntryFlags::HUGE));

        let addr_2m = entry.address() & 0x000f_ffff_fff0_0000;

        flags.remove(PTEntryFlags::HUGE);

        // Prepare PTE leaf page
        for i in 0..512 {
            let addr_4k = addr_2m + (i * PAGE_SIZE);
            unsafe {
                (*page).entries[i].clear();
                (*page).entries[i].set(set_c_bit(addr_4k), flags);
            }
        }

        entry.set(set_c_bit(virt_to_phys(page as VirtAddr)), flags);

        flush_tlb_global_sync();

        Ok(())
    }

    pub fn split_4k(mapping: Mapping) -> Result<(), ()> {
        match mapping {
            Mapping::Level0(_entry) => Ok(()),
            Mapping::Level1(entry) => PageTable::do_split_4k(entry),
            Mapping::Level2(_entry) => Err(()),
            Mapping::Level3(_entry) => Err(()),
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

    pub fn set_shared_4k(&mut self, vaddr: VirtAddr) -> Result<(), ()> {
        let mapping = self.walk_addr(vaddr);

        if let Err(_e) = PageTable::split_4k(mapping) {
            return Err(());
        }

        if let Mapping::Level0(entry) = self.walk_addr(vaddr) {
            PageTable::clear_c_bit(entry);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn set_encrypted_4k(&mut self, vaddr: VirtAddr) -> Result<(), ()> {
        let mapping = self.walk_addr(vaddr);

        if let Err(_e) = PageTable::split_4k(mapping) {
            return Err(());
        }

        if let Mapping::Level0(entry) = self.walk_addr(vaddr) {
            PageTable::set_c_bit(entry);
            Ok(())
        } else {
            Err(())
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
    ) -> Result<(), ()> {
        assert!(is_aligned(vaddr, PAGE_SIZE_2M));
        assert!(is_aligned(paddr, PAGE_SIZE_2M));

        let mapping = self.alloc_pte_2m(vaddr);

        if let Mapping::Level1(entry) = mapping {
            entry.set(set_c_bit(paddr), flags | PTEntryFlags::HUGE);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn unmap_2m(&mut self, vaddr: VirtAddr) {
        assert!(is_aligned(vaddr, PAGE_SIZE_2M));

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
    ) -> Result<(), ()> {
        let mapping = self.alloc_pte_4k(vaddr);

        if let Mapping::Level0(entry) = mapping {
            entry.set(set_c_bit(paddr), flags);
            Ok(())
        } else {
            Err(())
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

    pub fn phys_addr(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, ()> {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => {
                let offset = vaddr & (PAGE_SIZE - 1);
                if !entry.flags().contains(PTEntryFlags::PRESENT) {
                    return Err(());
                }
                Ok(entry.address() + offset)
            }
            Mapping::Level1(entry) => {
                let offset = vaddr & (PAGE_SIZE_2M - 1);
                if !entry.flags().contains(PTEntryFlags::PRESENT)
                    || !entry.flags().contains(PTEntryFlags::HUGE)
                {
                    return Err(());
                }

                Ok(entry.address() + offset)
            }
            Mapping::Level2(_entry) => Err(()),
            Mapping::Level3(_entry) => Err(()),
        }
    }

    pub fn map_region_4k(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), ()> {
        for addr in (start..end).step_by(PAGE_SIZE) {
            let offset = addr - start;
            self.map_4k(addr, phys + offset, flags)?;
        }
        Ok(())
    }

    pub fn unmap_region_4k(&mut self, start: VirtAddr, end: VirtAddr) {
        for addr in (start..end).step_by(PAGE_SIZE) {
            self.unmap_4k(addr);
        }
    }

    pub fn map_region_2m(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), ()> {
        for addr in (start..end).step_by(PAGE_SIZE_2M) {
            let offset = addr - start;
            self.map_2m(addr, phys + offset, flags)?;
        }
        Ok(())
    }

    pub fn unmap_region_2m(&mut self, start: VirtAddr, end: VirtAddr) {
        for addr in (start..end).step_by(PAGE_SIZE_2M) {
            self.unmap_2m(addr);
        }
    }

    pub fn map_region(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), ()> {
        let mut vaddr = start;
        let mut paddr = phys;

        while vaddr < end {
            if is_aligned(vaddr, PAGE_SIZE_2M)
                && is_aligned(paddr, PAGE_SIZE_2M)
                && vaddr + PAGE_SIZE_2M <= end
                && self.map_2m(vaddr, paddr, flags).is_ok()
            {
                vaddr += PAGE_SIZE_2M;
                paddr += PAGE_SIZE_2M;
                continue;
            }

            self.map_4k(vaddr, paddr, flags)?;
            vaddr += PAGE_SIZE;
            paddr += PAGE_SIZE;
        }

        Ok(())
    }

    pub fn unmap_region(&mut self, start: VirtAddr, end: VirtAddr) {
        let mut vaddr = start;

        while vaddr < end {
            let mapping = self.walk_addr(vaddr);

            match mapping {
                Mapping::Level0(entry) => {
                    entry.clear();
                    vaddr += PAGE_SIZE;
                }
                Mapping::Level1(entry) => {
                    entry.clear();
                    vaddr += PAGE_SIZE_2M;
                }
                _ => {
                    log::debug!("Can't unmap - address not mapped {:#x}", vaddr);
                }
            }
        }
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
