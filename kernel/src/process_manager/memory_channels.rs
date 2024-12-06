use crate::{address::VirtAddr, mm::PAGE_SIZE, process_manager::process_memory::ALLOCATION_RANGE_VIRT_START};

use super::{allocation::AllocationRange, process::ProcessID, process_paging::ProcessPageTableRef};

pub const INPUT_VADDR: u64 = 0xFF0000000000u64;
pub const OUTPUT_VADDR: u64 = 0xFF8000000000u64;

#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryChannel {
    pub input: AllocationRange,
    pub output: AllocationRange,
    pub owner: ProcessID,
    pub last_in_channel: bool,
    pub next: ProcessID,
}

impl MemoryChannel {

    pub fn allocate_input(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize) {
        self.input = self.allocate_range(page_table_ref, size, INPUT_VADDR);
    }

    pub fn allocate_output(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize) {
        self.output = self.allocate_range(page_table_ref, size, OUTPUT_VADDR);
    }

    pub fn inflate_input(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize) {
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        self.input.inflate(page_table_ref, page_count as u64, INPUT_VADDR);
    }

    pub fn inflate_output(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize) {
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        self.output.inflate(page_table_ref, page_count as u64, OUTPUT_VADDR);
    }

    pub fn copy_into(&mut self, source_addr: u64, page_table: u64, size: usize) {
        let copy_size = size + PAGE_SIZE - (size % PAGE_SIZE);
        let copy_page_count = copy_size / PAGE_SIZE;
        let target = VirtAddr::from(ALLOCATION_RANGE_VIRT_START);

        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        self.input.mount();

        page_table_ref.copy_address_range(VirtAddr::from(source_addr), copy_size as u64, target);

    }

    pub fn copy_out(&mut self, target_addr: u64, page_table: u64, size: usize) {
        let copy_size = size + PAGE_SIZE - (size % PAGE_SIZE);
        let copy_page_count = copy_size / PAGE_SIZE;
        let target = VirtAddr::from(ALLOCATION_RANGE_VIRT_START);
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);

        self.output.mount();

        page_table_ref.copy_address_range(VirtAddr::from(target), copy_size as u64, VirtAddr::from(target_addr));
    }

    fn allocate_range(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize, start: u64) -> AllocationRange{
        let mut r = AllocationRange::default();
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        r.allocate_with_start_addr(page_table_ref, page_count as u64, start);
        return r;
    }

}
