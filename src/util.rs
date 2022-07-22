use crate::types::PAGE_SIZE;
use core::arch::asm;

pub fn align_up(addr : usize, align: usize) -> usize {
	addr + (align -1) & !(align - 1)
}

pub fn page_align(addr : usize) -> usize {
	addr & !(PAGE_SIZE - 1)
}

pub fn page_align_up(addr : usize) -> usize {
	(addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub fn halt() {
	unsafe {
		asm!("hlt",
		     options(att_syntax));
	}
}
