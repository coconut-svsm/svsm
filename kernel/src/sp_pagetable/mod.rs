#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use crate::acpi::tables;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::write_cr3;
use crate::cpu::cpuid::cpuid_table;
use crate::cpu::features::{cpu_has_nx, cpu_has_pge};
use crate::cpu::flush_tlb_global_sync;
use crate::error::SvsmError;
use crate::locking::{LockGuard, SpinLock};
use crate::mm::alloc::{allocate_zeroed_page, free_page};
use crate::mm::vm::Mapping;
use crate::mm::{phys_to_virt, virt_to_phys, PGTABLE_LVL3_IDX_SHARED};
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use aes_gcm::aead::consts::True;
use aes_gcm::Error;
use alloc::borrow::ToOwned;
use bitflags::{bitflags, Flag, Flags};
use core::iter::Map;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::{cmp, ptr};
use alloc::string::{String, ToString};
use super::sp_pagetable::tmp_mapping::TemporaryPageMapping;
//use crate::mm::{PerCPUPageMappingGuard};


pub mod tmp_mapping;

extern crate alloc;
use alloc::boxed::Box;
use crate::sev::utils::{RMPFlags,rmp_adjust};
const PAGE_ENTRY_SIZE: usize = 512;
static ENCRYPT_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::new(0);
#[allow(dead_code)]
static MAX_PHYS_ADDR: ImmutAfterInitCell<u64> = ImmutAfterInitCell::uninit();
#[allow(dead_code)]
const CBIT_LOCATION: u32 = 0x8000001f;
#[allow(dead_code)]
const PSIZE_LOCATION: u32 = 0x80000008;
const ADDRESS_BITS: usize = 0x000ffffffffff000;
pub fn set_ecryption_mask_address_size() {
    let res = cpuid_table(CBIT_LOCATION).expect("CPUID table query error");
    let c_bit = res.ebx & 0x3f;
    let mask = 1u64 << c_bit;
    let _ = ENCRYPT_MASK.reinit(&(mask as usize));

    let res = cpuid_table(PSIZE_LOCATION).expect("CPUID table query error");
    let guest_phys_addr_size = (res.eax >> 16) & 0xff;
    let host_phys_addr_size = res.eax & 0xff;
    let phys_addr_size = if guest_phys_addr_size == 0 {
        host_phys_addr_size
    } else {
        guest_phys_addr_size
    };
    let effective_phys_addr_size = cmp::min(c_bit, phys_addr_size);
    let max_addr = 1 << effective_phys_addr_size;
    let _ = MAX_PHYS_ADDR.reinit(&max_addr);
}


fn get_ecryption_mask() -> usize {
    *ENCRYPT_MASK
}

fn strip_c_bit(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() & !get_ecryption_mask())
}

fn set_c_bit_in_address(addr: PhysAddr) -> PhysAddr {
    return PhysAddr::from(addr.bits() | get_ecryption_mask());
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PageFlags: u64 {
        const PRESENT =         1 << 0;
        const WRITABLE =        1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH =   1 << 3;
        const NO_CACHE =        1 << 4;
        const ACCESSED =        1 << 5;
        const DIRTY =           1 << 6;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;

        const NO_EXECUTE =      1 << 63;
    }
}

impl PageFlags {
    pub fn exec() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::ACCESSED | Self::DIRTY
    }

    pub fn data() -> Self {
        Self::PRESENT
            | Self::GLOBAL
            | Self::WRITABLE
            | Self::NO_EXECUTE
            | Self::ACCESSED
            | Self::DIRTY
    }

    pub fn data_ro() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::NO_EXECUTE | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_exec() -> Self {
        Self::PRESENT | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::NO_EXECUTE | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data_ro() -> Self {
        Self::PRESENT | Self::NO_EXECUTE | Self::ACCESSED | Self::DIRTY
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PageTableEntry(PhysAddr);

impl PageTableEntry {
    pub fn flags(&self) -> PageFlags {
        return PageFlags::from_bits_truncate(self.0.bits() as u64);
    }
    pub fn present(&self) -> bool {
        return self.flags().contains(PageFlags::PRESENT);
    }
    pub fn set(&mut self, addr: PhysAddr, flags: PageFlags) {
        self.0 = PhysAddr::from(addr.bits() as u64 | flags.bits());
    }
    pub fn address(&self) -> PhysAddr {
        return strip_c_bit(PhysAddr::from(self.0.bits() & ADDRESS_BITS));
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PageTablePage([PageTableEntry; PAGE_ENTRY_SIZE]);

impl Default for PageTablePage {
    fn default() -> Self {
        return PageTablePage {
            0: [PageTableEntry::default(); PAGE_ENTRY_SIZE],
        };
    }
}

impl Index<usize> for PageTablePage {
    type Output = PageTableEntry;
    fn index(&self, index: usize) -> &PageTableEntry {
        return &self.0[index];
    }
}

impl IndexMut<usize> for PageTablePage {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        return &mut self.0[index];
    }
}
#[repr(C)]
#[derive(Debug)]
pub struct PageTable(PageTablePage);

impl PageTable {

    pub fn index<const L: usize>(addr: VirtAddr) -> usize {
        addr.bits() >> (12 + L * 9) & 0x1ff
    }

}


#[repr(C)]
#[derive(Debug)]
pub struct PageTableReference {
    pub table: *mut PageTable,
    pub table_phy: PhysAddr,
    pub table_entry: TemporaryPageMapping,
    pub mounted: bool,
    pub pages: [PhysAddr; 256],
    pub free_pages: [bool; 256],
}
#[derive(Clone, Copy, Debug)]
pub enum SchalError {
    Allocation,
}

#[derive(Debug)]
pub enum TableLevelMapping<'a> {
    Level0(&'a mut PageTableEntry),
    Level1(&'a mut PageTableEntry),
    Level2(&'a mut PageTableEntry),
    Level3(&'a mut PageTableEntry),
}


/*

*/
impl PageTableReference {

    pub fn init(&mut self, addr: PhysAddr, mem: &[PhysAddr]){
        for i in self.pages.iter_mut() {
            *i = PhysAddr::from(0u64);
        }
        for i in self.free_pages.iter_mut() {
            *i = false;
        }

        for i in 0..mem.len() {
            self.pages[i] = mem[i];
            self.free_pages[i] = true;
        }
        self.mounted = false;
        self.table_phy = addr;
    }

    pub fn mount(&mut self) {
        if self.mounted {
            return;
        }
        self.table_entry = TemporaryPageMapping::create_4k(self.table_phy).unwrap();
        self.table =  self.table_entry.virt_addr().as_mut_ptr::<PageTable>();
        self.mounted = true;
    }
    pub fn unmount(&mut self) {
        if !self.mounted {
            return;
        }
        self.table_entry.delete();
        self.mounted = false;
    }

    fn print_flags(addr: PhysAddr, tabs: &str) {
        let v = addr.bits() as u64;

        let f = PageFlags::from_bits_truncate(v);
        for e in f.iter_names() {
            log::info!("{}{} set",tabs,e.0);
        }
        if v & get_ecryption_mask() as u64 != 0{
            log::info!("{}Encryption set",tabs)
        }

    }

    fn dump_next_level(&self, pentry: &PageTableEntry,level: i32, tabs: &str, va: usize) {
        if level == 0 {
            log::info!("{}Address: {:#x}, Virtual Addres: {:#x}",tabs, pentry.0,va);
            PageTableReference::print_flags(pentry.0, &(tabs.to_owned() + "     "));
            return;
        }

        if pentry.flags().contains(PageFlags::PRESENT){
            let m = TemporaryPageMapping::create_4k_clear12(pentry.0).expect("");
            let table = unsafe{ m.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() };
            for j in 0..table.0.len(){
                if table.0[j].0.bits() != 0 {
                    log::info!("{}Entry: Index {}, Address: {:#x}",tabs, j,table.0[j].0.bits() as u64 & 0x000f_ffff_ffff_f000u64);
                    PageTableReference::print_flags(table.0[j].0, &(tabs.to_owned() + "     "));
                    let tabel_entry = table.0[j];
                    self.dump_next_level(&tabel_entry,level-1,&(tabs.to_owned() + "     "), va + (j <<((12 + (level-1) * 9))));
                }
            }
            m.delete();
        }


    }

    pub fn dump(&self) {
        let table = unsafe {& (*self.table).0};
        for i in 0..table.0.len() {
            if table.0[i].0.bits() != 0 {
                log::info!("Entry: Index {}, Address: {:#x}", i,table.0[i].0.bits() as u64 & 0x000f_ffff_ffff_f000u64);
                PageTableReference::print_flags(table.0[i].0, "     ");
                let tabel_entry = table.0[i];
                self.dump_next_level(&tabel_entry, 3, "     ", i <<((12 + (3) * 9)));
            }
        }


    }



    fn page_walk(table: &mut PageTablePage, addr: VirtAddr) -> (TableLevelMapping<'_>, TemporaryPageMapping) {
        let index = PageTable::index::<3>(addr);
        let table_entry = table[index];
        log::info!("Checking Entry: {:#x} (index: {})", table_entry.0, index);

        if !table_entry.flags().contains(PageFlags::PRESENT) {
            log::info!("Entry {} in level 3 not found", index);
            return (TableLevelMapping::Level3(&mut table[index]), Default::default())
        }

        let m3 = TemporaryPageMapping::create_4k_clear12(table_entry.0).expect("");
        
        let table = unsafe{ m3.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() };

        let index = PageTable::index::<2>(addr);
        let table_entry = table[index];
        log::info!("Checking Entry: {:#x} (index: {})", table_entry.0, index);
        if !table_entry.flags().contains(PageFlags::PRESENT) {
            return (TableLevelMapping::Level2(&mut table[index]), m3)
        }
        
        let m2 = TemporaryPageMapping::create_4k_clear12(table_entry.0).expect("");
        m3.delete();
        let table =  unsafe{ m2.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() };

        let index = PageTable::index::<1>(addr);
        let table_entry = table[index];
        log::info!("Checking Entry: {:#x} (index: {})", table_entry.0, index);
        if !table_entry.flags().contains(PageFlags::PRESENT) {
            return (TableLevelMapping::Level1(&mut table[index]), m2)
        }

        let m1 = TemporaryPageMapping::create_4k_clear12(table_entry.0).expect("");
        m2.delete();
        let table =  unsafe{ m1.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() }; 

        let index = PageTable::index::<0>(addr);
        return (TableLevelMapping::Level0(&mut table[index]), m1)

    }


    fn get_free_pages(&mut self) -> PhysAddr {
        for i in 0..self.free_pages.len() {
            if self.free_pages[i] {
                self.free_pages[i] = false;
                log::info!("New Page allocated: {:#x}", self.pages[i]);
                return self.pages[i];
            }
        }
        return PhysAddr::from(0u64);
    }

    pub fn page_walk_pub(&self, addr: VirtAddr) -> PhysAddr {
        log::info!("Searching for entry {:#x}", addr.bits());
        let walk = PageTableReference::page_walk(unsafe {&mut (*self.table).0}, addr);
        if let TableLevelMapping::Level0(page_entry) = walk.0 {
            let ret = page_entry.0;
            walk.1.delete();
            ret
        } else {
            PhysAddr::from(0u64)
        }

    }

    pub fn map_4k_page(&mut self, target: VirtAddr, addr: PhysAddr, flags: PageFlags) -> Result<(), SchalError>{
        /*
        First comes a walk along the table to find if we have a free slot we can use for the
        current page        
         */
        log::info!("Trying to find empty space in page table");
        let walk = PageTableReference::page_walk(unsafe {&mut (*self.table).0}, target);
        let mut current_mapping = walk.0;
        let mut current_tmp = walk.1;
        let mut finished = false;
        log::info!("Allocating if needed");
        //let r = self as *mut PageTableReference;
        let table_flages = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE | PageFlags::ACCESSED;
        while !finished {
            match current_mapping {
                TableLevelMapping::Level0(_) => {
                    finished = true;
                    log::info!("Finished creating new mappings");
                },
                TableLevelMapping::Level1(ref mut table_entry) => {
                    //let new_self = unsafe {&mut *r};
                    log::info!("Created new level0 mapping");
                    let page_addr = self.get_free_pages();
                    
                    let new_tmp = TemporaryPageMapping::create_4k(page_addr).unwrap();
                    table_entry.set(set_c_bit_in_address(page_addr), table_flages);
                    current_tmp.delete();
                    current_tmp =new_tmp;
                    
                    let index = PageTable::index::<0>(target);
                    let e = unsafe { new_tmp.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() };
                    current_mapping = TableLevelMapping::Level0(&mut e[index]);
                    
                
                },
                TableLevelMapping::Level2(ref mut table_entry) => {
                    //let new_self = unsafe {&mut *r};
                    log::info!("Created new level1 mapping");
                    let page_addr = self.get_free_pages();
                    let new_tmp = TemporaryPageMapping::create_4k(page_addr).unwrap();
                    table_entry.set(set_c_bit_in_address(page_addr), table_flages);
                    current_tmp.delete();
                    current_tmp = new_tmp;
                    
                    let index = PageTable::index::<1>(target);
                    let e = unsafe { new_tmp.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() };
                    current_mapping = TableLevelMapping::Level1(&mut e[index]); 
                    

                },
                TableLevelMapping::Level3(ref mut table_entry) => {
                    //let new_self = unsafe {&mut *r};
                    log::info!("Created new level2 mapping");
                    let page_addr = self.get_free_pages();
                    let new_tmp = TemporaryPageMapping::create_4k(page_addr).unwrap();
                    table_entry.set(set_c_bit_in_address(page_addr), table_flages);
                    current_tmp.delete();
                    current_tmp = new_tmp;
                   
                    let index = PageTable::index::<2>(target);
                    let e = unsafe { new_tmp.virt_addr().as_mut_ptr::<PageTablePage>().as_mut().unwrap() };
                    current_mapping = TableLevelMapping::Level2(&mut e[index]);
                    

                },
            };
        };
        
        if let TableLevelMapping::Level0(page_entry) = current_mapping {
            log::info!("Adding address at {:#x}", target);
            Ok(page_entry.set(set_c_bit_in_address(addr),flags))
        } else {
            Err(SchalError::Allocation)
        }

    }


}



#[derive(Debug)]
pub struct Pointer<T> {
    pub pointer: *mut T
}


impl<T> Deref for Pointer<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.pointer }
    }
}

impl<T> DerefMut for Pointer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.pointer }
    }
}