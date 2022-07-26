use crate::cpu::msr::{write_msr, MSR_GS_BASE};
use crate::mm::alloc::allocate_page;
use crate::sev::GHCB;
use crate::types::VirtAddr;
use core::ptr;
use core::arch::asm;

pub struct PerCpu {
	ghcb : *mut GHCB,
}

impl PerCpu {
	pub const fn new() -> Self {
		PerCpu {
			ghcb : ptr::null_mut(),
		}
	}

	pub fn setup(&mut self) -> Result<(), ()> {
		let ghcb_page = allocate_page().expect("Failed to allocate GHCB page");

		self.ghcb = ghcb_page as *mut GHCB;

		let gs_base : u64 = (self as *const PerCpu) as u64;
		write_msr(MSR_GS_BASE, gs_base);

		unsafe { (*self.ghcb).init() }
	}
}

unsafe impl Sync for PerCpu { }

pub fn this_cpu_ghcb() -> &'static mut GHCB {
	unsafe {
		// FIXME: Implement proper offset calculation
		let offset = 0;

		let mut ghcb_addr : VirtAddr;

		asm!("movq %gs:(%rax), %rdx", in("rax") offset, out("rdx") ghcb_addr, options(att_syntax));

		(ghcb_addr as *mut GHCB).as_mut().unwrap()
	}
}
