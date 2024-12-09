use crate::{address::{Address, PhysAddr, VirtAddr}, paddr_as_table, process_manager::process_memory::allocate_page, sev::{rmp_adjust, RMPFlags}};
use crate::{paddr_as_slice, paddr_as_u64_slice, vaddr_as_u64_slice, vaddr_as_slice, map_paddr, strip_paddr};
use crate::process_manager::memory_helper::{strip_c_bit, set_c_bit_in_address};
use crate::mm::PerCPUPageMappingGuard;
use bitflags::{bitflags};
use elf::{Elf64Phdr, Elf64PhdrFlags};
use crate::mm::PAGE_SIZE;
use igvm_defs::PAGE_SIZE_4K;
use core::ops::{Index, IndexMut};
use core::slice;
use core::mem::replace;
use crate::types::PageSize;
use super::process_memory::{ALLOCATION_RANGE_VIRT_START, PGD, PMD, PTE, PUD};
use crate::process_manager::allocation::AllocationRange;
use core::ffi::CStr;
use super::memory_helper::{ZERO_PAGE};

// TP: Trusted Process
const TP_STACK_START_VADDR: u64 = 0x80_0000_0000;
const TP_MANIFEST_START_VADDR: u64 = 0x100_0000_0000;
const TP_LIBOS_START_VADDR: u64 = 0x180_0000_0000;

// Flags for the Page Table
// In general all Trusted Processes need to
// have user accessable set
bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ProcessPageFlags: u64 {
        const PRESENT =         1 << 0;
        const WRITABLE =        1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH =   1 << 3;
        const NO_CACHE =        1 << 4;
        const ACCESSED =        1 << 5;
        const DIRTY =           1 << 6;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;

        //const NO_EXECUTE =      1 << 63;
        const NO_EXECUTE =      0;
    }
}

impl ProcessPageFlags {
    pub fn exec() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::ACCESSED |
        Self::DIRTY | Self::USER_ACCESSIBLE
    }

    pub fn data() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::WRITABLE |
        Self::NO_EXECUTE | Self::ACCESSED | Self::DIRTY |
        Self::USER_ACCESSIBLE
    }

    pub fn data_ro() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::NO_EXECUTE |
        Self::ACCESSED | Self::DIRTY | Self::USER_ACCESSIBLE
    }

    pub fn task_exec() -> Self {
        Self::PRESENT | Self::ACCESSED | Self::DIRTY |
        Self::USER_ACCESSIBLE
    }

    pub fn task_data() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::NO_EXECUTE |
        Self::ACCESSED | Self::DIRTY | Self::USER_ACCESSIBLE
    }

    pub fn task_data_ro() -> Self {
        Self::PRESENT | Self::NO_EXECUTE | Self::ACCESSED |
        Self::DIRTY | Self::USER_ACCESSIBLE
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcessPageTableEntry(pub PhysAddr);

impl ProcessPageTableEntry {
    pub fn flags(&self) -> ProcessPageFlags {
        return ProcessPageFlags::from_bits_truncate(self.0.bits() as u64);
    }
    pub fn set(&mut self, addr: PhysAddr, flags: ProcessPageFlags) {
        self.0 = set_c_bit_in_address(PhysAddr::from(addr.bits() as u64 | flags.bits()));
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ProcessPageTablePage([ProcessPageTableEntry; 512]);

impl Default for ProcessPageTablePage {
    fn default() -> Self {
        return ProcessPageTablePage {
            0: [ProcessPageTableEntry::default(); 512],
        };
    }
}

impl Index<usize> for ProcessPageTablePage {
    type Output = ProcessPageTableEntry;
    fn index(&self, index: usize) -> &ProcessPageTableEntry {
        return &self.0[index];
    }
}

impl IndexMut<usize> for ProcessPageTablePage {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        return &mut self.0[index];
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ProcessTableLevelMapping {
    PGD(PhysAddr,usize),
    PUD(PhysAddr,usize),
    PMD(PhysAddr,usize),
    PTE(PhysAddr,usize),
}


#[repr(C)]
#[derive(Debug)]
pub struct ProcessPageTable(pub ProcessPageTablePage);

impl ProcessPageTable {

    pub fn index<const L: usize>(addr: VirtAddr) -> usize {
        addr.bits() >> (12 + L * 9) & 0x1ff
    }

    pub fn index_arg(i: usize, addr: VirtAddr) -> usize {
        addr.bits() >> (12 + i * 9) & 0x1ff
    }

    pub fn init(&mut self){
        self.0 = Default::default();
    }
}

#[repr(C)]

#[derive(Debug, Copy, Clone, Default)]
pub struct ProcessPageTableRef {
    pub process_page_table: PhysAddr,
}


impl ProcessPageTableRef {

    pub fn init(&mut self) {
        self.process_page_table = allocate_page();
        let (_mapping, table) = paddr_as_u64_slice!(self.process_page_table);
        for i in 0..512 {
            table[i] = 0;
        }
    }

    fn init_vmpl1(&mut self){
        self.process_page_table = allocate_page();
        let (mapping, table) = paddr_as_u64_slice!(self.process_page_table);
        for i in 0..512 {
            table[i] = 0;
        }
        rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    }

    pub fn set_external_table(&mut self, pgd_addr: u64) {
        self.process_page_table = PhysAddr::from(pgd_addr);
    }

    pub fn print_table(&self) {
        self.print_table_helper(self.process_page_table, PGD);
    }

    fn print_table_helper(&self, paddr: PhysAddr, level: usize) {
        let (_mapping, table) = paddr_as_table!(paddr);
        let dist = "    ".repeat(PGD-level);
        for i in 0..512 {
            let page: ProcessPageTableEntry = table[i];
            if usize::from(page.0) != 0 {
                log::info!("{}Entry: Index {}, Address: {:#x}, Flags {:#b}",dist, i, page.0, usize::from(page.0) & 0x1FF);
                //We might get 4MB pages when taking in tables from the guest
                if level == PMD {
                    if usize::from(page.0) & 0x80 != 0 {
                        //Found hugh page
                        return;
                    }
                }
                if level > PTE {
                    let addr = PhysAddr::from(usize::from(strip_c_bit(page.0)) & !0x1FF );
                    self.print_table_helper(addr, level-1);
                }
            } 
        }

    }

    fn add_region_vaddr(&self, vaddr: VirtAddr, data: &[u8]) {
        let page_flags = ProcessPageFlags::data();
        let len = data.len();
        let required_pages = len / 4096;
        for i in 0..required_pages {
            let new_page = allocate_page();
            let (_mapping, mapping_vaddr) = map_paddr!(new_page);
            let mapped_page = unsafe { &mut *mapping_vaddr.as_mut_ptr::<[u8;4096]>() };
            for j in 0..4096 {
                mapped_page[j] = data[j + i * 4096];
            }
            let target_addr = vaddr + i * 4096;
            self.map_4k_page(VirtAddr::from(target_addr), new_page, page_flags);
            rmp_adjust(mapping_vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap()
        }
    }

    fn add_region(&self, hdr: Elf64Phdr, elf: &[u8]) {

        let offset = hdr.p_offset;
        let filesize = hdr.p_filesz;
        let memsz = hdr.p_memsz;
        let vaddr = hdr.p_vaddr;
        let flags = hdr.p_flags;

        let mut page_flags =
            ProcessPageFlags::PRESENT | ProcessPageFlags::GLOBAL |
            ProcessPageFlags::DIRTY | ProcessPageFlags::USER_ACCESSIBLE;
        if !flags.contains(Elf64PhdrFlags::EXECUTE) {
            page_flags = page_flags | ProcessPageFlags::NO_EXECUTE;
        }
        if flags.contains(Elf64PhdrFlags::WRITE){
            page_flags = page_flags | ProcessPageFlags::WRITABLE;
        }
       
        if memsz == 0 {
            return;
        }
        let required_pages = memsz / 4096 + 1;

        let mut file_size = filesize;
        for i in 0..required_pages {
            let new_page = allocate_page();
            let (mapping, mapping_vaddr) = map_paddr!(new_page);
            let mapped_page = unsafe { &mut *mapping_vaddr.as_mut_ptr::<[u8;4096]>()};
            rmp_adjust(mapping_vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
            for j in 0..4096 {
                if file_size > 0 {
                    mapped_page[j] = elf[(offset+(j as u64)) as usize + (i * PAGE_SIZE_4K) as usize];
                    file_size -= 1;
                } else {
                    mapped_page[j] = 0;
                }
            }
            let target_addr = vaddr + i * PAGE_SIZE_4K;
            self.map_4k_page(VirtAddr::from(target_addr), new_page, page_flags);
        }



    }

    fn build_from_elf(&self, _elf_addr: *mut u8, elf_file: &[u8], elf: elf::Elf64File<'static>) -> VirtAddr{

        //log::info!("Elf contents: {:?}",elf);
        let program_header_entry_number = elf.elf_hdr.e_phnum;
        for i in 0..program_header_entry_number {
            let program_header: Elf64Phdr = elf.read_phdr(i);
            if program_header.p_type != 1 {
                continue;
            }
            //log::info!("Program Header({i}): {:?}", program_header);
            self.add_region(program_header, elf_file );
        }
        //Add stack
        self.add_stack(VirtAddr::from(TP_STACK_START_VADDR), 8);
        self.print_table();
        VirtAddr::from(elf.elf_hdr.e_entry)
    }

    pub fn add_manifest(&self, data: VirtAddr, size: u64) {
        let data: *mut u8 = data.as_mut_ptr::<u8>();
        let data = unsafe { slice::from_raw_parts(data, size as usize) };
        self.add_region_vaddr(VirtAddr::from(TP_MANIFEST_START_VADDR), data);
    }

    pub fn add_libos(&self, data: VirtAddr, size: u64) {
        let data: *mut u8 = data.as_mut_ptr::<u8>();
        let data = unsafe { slice::from_raw_parts(data, size as usize) };
        self.add_region_vaddr(VirtAddr::from(TP_LIBOS_START_VADDR), data);
    }

    pub fn add_function(&self, data:VirtAddr, size: u64) {
        let data: *mut u8 = data.as_mut_ptr::<u8>();
        let data = unsafe { slice::from_raw_parts(data, size as usize) };
        self.add_region_vaddr(VirtAddr::from(0x140_0000_0000u64), data);
    }

    pub fn add_pages(&self, start: VirtAddr, size: u64, flags: ProcessPageFlags) {
        for i in 0..(size as usize) {
            let new_page = allocate_page();
            let (mapping, s) = paddr_as_slice!(new_page);
            _ = replace(s, ZERO_PAGE);
            self.map_4k_page(start + i * PAGE_SIZE, new_page, flags);
            rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        }
    }

    pub fn add_stack(&self, start: VirtAddr, size: u64){
        for i in 0..(size as usize) {
            let new_page = allocate_page();
            let (mapping, s) = paddr_as_slice!(new_page);
            _ = replace(s, ZERO_PAGE);
            self.map_4k_page(start + i * PAGE_SIZE, new_page, ProcessPageFlags::data());
            rmp_adjust(mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
        }
    }

    pub fn build_from_file(&mut self, data: VirtAddr, size: u64) -> VirtAddr{

        self.init_vmpl1();
        let elf_addr: *mut u8 = data.as_mut_ptr::<u8>();
        let elf_raw = unsafe { slice::from_raw_parts(elf_addr, size as usize) };
        match elf::Elf64File::read(elf_raw) {
            Ok(e) => self.build_from_elf(elf_addr,elf_raw, e),
            Err(e) => {log::info!("error reading ELF: {}", e);
                       panic!()},
        }
    }


    pub fn copy_address_range(&self, origin: VirtAddr, size: u64, target: VirtAddr) {
        //All copies extend to the complete page
        let copy_page_count = size / PAGE_SIZE_4K;
        for i in 0..copy_page_count {
            // Mapping the src, dst to as u64;512 slices
            let origin_phys = self.get_page(origin + 4096usize * (i as usize));
            let (_mapping,origin_slice) = paddr_as_slice!(origin_phys);
            let target_vaddr = target + 4096usize * (i as usize);
            let target_slice = vaddr_as_slice!(target_vaddr);
            // Copying the src to dst
            _ = replace(target_slice, *origin_slice);
        }
    }

    pub fn get_page(&self, addr: VirtAddr) -> PhysAddr{
        //Mapping the page table into Memory and get the next layer based on the address
        let (_pgd_mapping, pgd_table) = paddr_as_table!(self.process_page_table);
        let mut table: &mut ProcessPageTablePage = pgd_table;
        let mut index = ProcessPageTable::index::<PGD>(addr);
        let mut table_entry = table[index];


        let mut _mapping: PerCPUPageMappingGuard;
        //let mut prev_addr = table_entry.0;

        if !table_entry.flags().contains(ProcessPageFlags::PRESENT) {
            return PhysAddr::null();
        }

        //Iterating through page table until Address is found
        //Otherwise we fail and return null
        for i in [PUD, PMD, PTE] {
            //prev_addr = strip_paddr!(table_entry.0);
            (_mapping,table) = paddr_as_table!(strip_paddr!(table_entry.0));
            index = ProcessPageTable::index_arg(i, addr);
            table_entry = table[index];
            if !table_entry.flags().contains(ProcessPageFlags::PRESENT){
                return PhysAddr::null();
            }
        }
        strip_paddr!(table_entry.0)
    }

    fn page_walk(&self, table: &ProcessPageTablePage,
                 paddr: PhysAddr, addr: VirtAddr)
                 -> ProcessTableLevelMapping {
        let mut index = ProcessPageTable::index::<PGD>(addr);
        let mut table_entry = table[index];

        let mut _mapping: PerCPUPageMappingGuard;
        let mut table: &mut ProcessPageTablePage;
        let mut prev_addr = table_entry.0;

        if !table_entry.flags().contains(ProcessPageFlags::PRESENT) {
            return ProcessTableLevelMapping::PGD(paddr,index);
        }
        for i in [PUD, PMD, PTE] {
            prev_addr = strip_paddr!(table_entry.0);
            (_mapping, table) = paddr_as_table!(strip_paddr!(table_entry.0));
            index = ProcessPageTable::index_arg(i, addr);
            table_entry = table[index];
            if !table_entry.flags().contains(ProcessPageFlags::PRESENT){
                return match i {
                    PUD => ProcessTableLevelMapping::PUD(prev_addr, index),
                    PMD => ProcessTableLevelMapping::PMD(prev_addr, index),
                    PTE => ProcessTableLevelMapping::PTE(prev_addr, index),
                    _ => panic!("Cannot happen"),
                }
            }
        }
        return ProcessTableLevelMapping::PTE(prev_addr, index);
    }

    pub fn virt_to_phys(&self, vaddr: VirtAddr) -> PhysAddr {
        let (_pgd_mapping, pgd_table) = paddr_as_table!(self.process_page_table);
        let mut current_mapping = self.page_walk(&pgd_table, self.process_page_table, vaddr);
        //log::info!("Current Mapping {:?}", current_mapping);
        match current_mapping {
            ProcessTableLevelMapping::PTE(addr, index) => {
                let (_mapping, table) = paddr_as_u64_slice!(addr);
                return PhysAddr::from(table[index] & !0xFFFF000000000FFF);
            }
            _ => return PhysAddr::null()
        }

    }


    /// Takes the page table of the guest OS and copies the
    /// specified starteding from addr and edning at addr + size * pagesize
    /// into a AllocationRange in the Monitor
    pub fn copy_data_from_guest(addr: u64, size: u64, page_table: u64) -> (VirtAddr, AllocationRange){

        let copy_size = size + (PAGE_SIZE_4K - size % PAGE_SIZE_4K); //Extend size ot full page size
        let copy_page_count = copy_size / PAGE_SIZE_4K;
        let mut alloc_range = AllocationRange(0,0);
        alloc_range.allocate(copy_page_count);
        let target = VirtAddr::from(ALLOCATION_RANGE_VIRT_START);

        let mut page_table_ref = ProcessPageTableRef::default();

        page_table_ref.set_external_table(page_table);

        page_table_ref.copy_address_range(VirtAddr::from(addr), copy_size, target);

        (target, alloc_range)
    }

    pub fn copy_data_from_guest_to(addr: u64, size: u64, page_table: u64, dst: u64) {
        let copy_size = size + (PAGE_SIZE_4K - size % PAGE_SIZE_4K);
        let copy_page_count = copy_size / PAGE_SIZE_4K;
        let target = VirtAddr::from(dst);

        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);
        page_table_ref.copy_address_range(VirtAddr::from(addr), copy_size, target);
    }


    pub fn map_4k_page(&self, target: VirtAddr, addr: PhysAddr, flags: ProcessPageFlags) {
        let (_pgd_mapping, pgd_table) = paddr_as_table!(self.process_page_table);
        let mut current_mapping = self.page_walk(&pgd_table, self.process_page_table, target);

        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
                          ProcessPageFlags::USER_ACCESSIBLE | ProcessPageFlags::ACCESSED;

        let mut finished = false;

        while !finished {
            match current_mapping {
                ProcessTableLevelMapping::PTE(table_phys, index) => {
                    let (pte_mapping, pte_table) = paddr_as_table!(table_phys);
                    rmp_adjust(pte_mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                    pte_table[index].set(addr, flags);
                    finished = true;
                },
                ProcessTableLevelMapping::PMD(table_phys, index) =>  {
                    let (pmd_mapping, pmd_table) = paddr_as_table!(table_phys);
                    rmp_adjust(pmd_mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                    let free_page = allocate_page();
                    pmd_table[index].set(free_page, table_flags);
                    current_mapping =
                        ProcessTableLevelMapping::PTE(free_page, ProcessPageTable::index::<PTE>(target));
                },
                ProcessTableLevelMapping::PUD(table_phys, index) => {
                    let (pud_mapping, pud_table) = paddr_as_table!(table_phys);
                    let free_page = allocate_page();
                    rmp_adjust(pud_mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                    pud_table[index].set(free_page, table_flags);
                    current_mapping =
                        ProcessTableLevelMapping::PMD(free_page, ProcessPageTable::index::<PMD>(target));
                },
                ProcessTableLevelMapping::PGD(table_phys, index) => {
                    let (pgd_mapping, pgd_table) = paddr_as_table!(table_phys);
                    rmp_adjust(pgd_mapping.virt_addr(), RMPFlags::VMPL1 | RMPFlags::RWX , PageSize::Regular).unwrap();
                    let free_page = allocate_page();
                    pgd_table[index].set(free_page, table_flags);
                    current_mapping =
                        ProcessTableLevelMapping::PUD(free_page, ProcessPageTable::index::<PUD>(target));
                }
            }
        }
    }
}
