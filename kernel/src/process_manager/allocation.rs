use crate::process_manager::process_memory::allocate_page;
use crate::mm::PAGE_SIZE;
use crate::address::{Address, VirtAddr};
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::cpu::control_regs::read_cr3;
use crate::{paddr_as_slice, map_paddr, vaddr_as_slice};
use crate::mm::PerCPUPageMappingGuard;

const ALLOCATION_VADDR_START: u64 = 0x30000000000u64;
pub const DEFAULT_ALLOCATION_RANGE_MOUNT: usize = 6;
const PGD_SHIFT: u64 = 39;
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocationRange(pub u64, pub u64);

impl AllocationRange {

    pub fn allocate(&mut self, pages: u64){
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);
        self.allocate_(&mut page_table_ref, pages, ALLOCATION_VADDR_START, true);
    }

    pub fn allocate_with_start_addr(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64){
        self.allocate_(page_table_ref, pages, start_addr, false);
    }

    fn allocate_(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64, mount: bool){
        // Reuses the Process page managment to add new memory to the Monitor
        //let mut page_table_ref = ProcessPageTableRef::default();
        //page_table_ref.set_external_table(read_cr3().bits() as u64);
        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED;

        let start_address = VirtAddr::from(start_addr);

        for i in 0..(pages as usize) {
            let current_page = allocate_page();
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        };
        if mount {
            let (_mapping, pgd) = paddr_as_slice!(read_cr3());
            self.0 = pgd[DEFAULT_ALLOCATION_RANGE_MOUNT];
            self.1 = pages;
        } else {
            let offset = start_addr >> PGD_SHIFT;
            let (_mapping, pgd) = paddr_as_slice!(page_table_ref.process_page_table);
            self.0 = pgd[offset as usize];
            self.1 = pages;
        }
    }

    pub fn inflate(&mut self, page_table_ref: &mut ProcessPageTableRef, pages: u64, start_addr: u64) {
        if self.1 >= pages {
            return;
        }
        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
        ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED;
        let start_address = VirtAddr::from(start_addr);
        let begin = self.1;
        for i in 0..(pages as usize) {
            let current_page = allocate_page();
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        }
        self.1 = pages;
    }

    pub fn mount(&self) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        pgd[DEFAULT_ALLOCATION_RANGE_MOUNT] = self.0;
    }

    pub fn mount_at(&self, loc: usize) -> u64 {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        let old_table = pgd[loc];
        pgd[loc] = self.0;
        return old_table;
    }

    pub fn reset_mount(&self, loc: usize, t: u64) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        pgd[loc] = t;
    }

    pub fn delete(&self) {

    }

}
