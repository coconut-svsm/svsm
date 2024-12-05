use crate::process_manager::process_memory::allocate_page;
use crate::mm::PAGE_SIZE;
use crate::address::{Address, VirtAddr};
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_manager::process_paging::ProcessPageFlags;
use super::process_memory::{ALLOCATION_RANGE_VIRT_START, PGD};
use crate::cpu::control_regs::read_cr3;
use crate::{paddr_as_slice, map_paddr, vaddr_as_slice};
use crate::mm::PerCPUPageMappingGuard;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocationRange(pub u64, pub u64);

 impl AllocationRange {

    pub fn allocate(&mut self, pages: u64){
        // Allocates a new memory range for the Monitor

        // Currently the start virtual address is fixed to ALLOCATION_RANGE_VIRT_START
        let start_address = VirtAddr::from(ALLOCATION_RANGE_VIRT_START);

        // Reuses the Process page managment to add new memory to the Monitor
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);
        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
                          ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED;

        for i in 0..(pages as usize) {
            let current_page = allocate_page();
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        };

        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        let pgd_index = start_address.to_pgtbl_idx::<PGD>();
        self.0 = pgd[pgd_index];
        self.1 = pages;

    }

    pub fn mount(&self) {
        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        pgd[6] = self.0;
    }

    pub fn delete(&self) {
        todo!("Not implemented");
    }

}
