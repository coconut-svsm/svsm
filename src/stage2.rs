#![no_std]
#![no_main]

pub mod allocator;
pub mod pagetable;
pub mod locking;
pub mod string;
pub mod serial;
pub mod fw_cfg;
pub mod cpuid;
pub mod util;
pub mod msr;
pub mod sev;
pub mod io;
pub mod boot;

use pagetable::{PageTable};
use core::panic::PanicInfo;
use allocator::{init_heap, print_heap_info};
use sev::{GHCB, sev_status_init, sev_init, sev_es_enabled};
use fw_cfg::fw_cfg_read_e820;
use cpuid::dump_cpuid_table;
use util::halt;

#[macro_use]
extern crate bitflags;
extern crate memoffset;

extern "C" {
	pub static mut pgtable : PageTable;
}

static mut GHCB: Option<&mut GHCB> = None;

fn init_ghcb() {
	unsafe {
		GHCB = GHCB::create();
		if let None = &mut GHCB {
			loop {};
		}
	}
}

#[no_mangle]
pub extern "C" fn stage2_main() {
	sev_status_init();
	init_heap();
	if sev_es_enabled() {
		init_ghcb();
	}
	println!("SVSM Stage2 Loader");
	print_heap_info();
	sev_init();
	fw_cfg_read_e820();
	dump_cpuid_table();
	/*
	unsafe {
		let mapping = pgtable.walk_addr(0);
		match PageTable::split_4k(mapping) {
			Ok(_r) => println!("Split successfull"),
			Err(_r) => println!("Split failed"),
		}

		match pgtable.walk_addr(0) {
			Mapping::Level0(entry) => println!("Address mapped at Level 0 (entry: {:#016x})", entry.0),
			Mapping::Level1(entry) => println!("Address mapped at Level 1 (entry: {:#016x})", entry.0),
			Mapping::Level2(entry) => println!("Address mapped at Level 2 (entry: {:#016x})", entry.0),
			Mapping::Level3(entry) => println!("Address mapped at Level 3 (entry: {:#016x})", entry.0),
		}

	}
	*/
	panic!("Road ends here!");
}

#[panic_handler]
fn panic(info : &PanicInfo) -> ! {
	println!("Panic: {}", info);
	loop { halt(); }
}

