use log::Metadata;

use crate::{address::{PhysAddr, VirtAddr}, cpu::flush_tlb_global, map_paddr, mm::{PerCPUPageMappingGuard, PAGE_SIZE}, paddr_as_slice, process_manager::process_memory::ALLOCATION_RANGE_VIRT_START, vaddr_as_slice};

use super::{allocation::AllocationRange, process::ProcessID, process_paging::ProcessPageTableRef};

pub const INPUT_VADDR: u64 = 0x28000000000u64;
pub const OUTPUT_VADDR: u64 = 0x30000000000u64;

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
        let target = VirtAddr::from(ALLOCATION_RANGE_VIRT_START);
        self.input.mount();
        ProcessPageTableRef::copy_data_from_guest_to(source_addr, size as u64, page_table, ALLOCATION_RANGE_VIRT_START);
    }

    pub fn copy_out(&mut self, target_addr: u64, page_table: u64, size: usize) {
        let copy_size = size + PAGE_SIZE - (size % PAGE_SIZE);
        let source = VirtAddr::from(ALLOCATION_RANGE_VIRT_START);
        self.output.mount();
        ProcessPageTableRef::copy_data_to_guest(target_addr, copy_size as u64, page_table);
    }


    fn allocate_range(&mut self, page_table_ref: &mut ProcessPageTableRef, size: usize, start: u64) -> AllocationRange{
        let mut r = AllocationRange::default();
        let page_count = (size + PAGE_SIZE - (size % PAGE_SIZE)) / PAGE_SIZE;
        r.allocate_with_start_addr(page_table_ref, page_count as u64, start);
        return r;
    }

}
