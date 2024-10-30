use crate::process_manager::process_memory::allocate_page;
use crate::mm::PAGE_SIZE;
use crate::address::{Address, VirtAddr};
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_manager::process_paging::ProcessPageFlags;
use crate::cpu::control_regs::read_cr3;
use crate::{paddr_as_slice, map_paddr, vaddr_as_slice};
use crate::mm::PerCPUPageMappingGuard;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocationRange(pub u64, pub u64);

 impl AllocationRange {

    pub fn allocate(&mut self, pages: u64){
        // Reuses the Process page managment to add new memory to the Monitor
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(read_cr3().bits() as u64);
        let table_flags = ProcessPageFlags::PRESENT | ProcessPageFlags::WRITABLE |
                          ProcessPageFlags::DIRTY | ProcessPageFlags::ACCESSED;

        let start_address = VirtAddr::from(0x30000000000u64);

        for i in 0..(pages as usize) {
            let current_page = allocate_page();
            page_table_ref.map_4k_page(start_address + i * PAGE_SIZE, current_page, table_flags);
        };

        let (_mapping, pgd) = paddr_as_slice!(read_cr3());
        self.0 = pgd[6];
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
