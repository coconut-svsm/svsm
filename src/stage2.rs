#![no_std]
#![no_main]
#![feature(const_mut_refs)]

pub mod allocator;
pub mod pagetable;
pub mod locking;
pub mod console;
pub mod string;
pub mod serial;
pub mod fw_cfg;
pub mod cpuid;
pub mod util;
pub mod boot;
pub mod msr;
pub mod sev;
pub mod io;

use sev::{GHCB, sev_status_init, sev_init, sev_es_enabled, GHCBIOPort};
use serial::{DEFAULT_SERIAL_PORT, SERIAL_PORT, SerialPort};
use allocator::{init_heap, print_heap_info};
use cpuid::dump_cpuid_table;
use core::panic::PanicInfo;
use pagetable::PageTable;
use core::cell::RefCell;
use console::WRITER;
use fw_cfg::FwCfg;
use util::halt;

#[macro_use]
extern crate bitflags;
extern crate memoffset;

extern "C" {
	pub static mut pgtable : PageTable;
	pub static mut boot_ghcb : GHCB;
}

static SEV_ES_IO : GHCBIOPort = GHCBIOPort { ghcb : unsafe { RefCell::new(&mut boot_ghcb) } };
static mut SEV_ES_SERIAL : SerialPort = SerialPort { driver : &SEV_ES_IO, port : SERIAL_PORT };

fn setup_env() {
	sev_status_init();
	init_heap();

	if !sev_es_enabled() {
		unsafe { DEFAULT_SERIAL_PORT.init(); }
		panic!("SEV-ES not available");
	}

	unsafe {
		if let Err(_e) = boot_ghcb.init() {
			halt();
		}
	}

	unsafe { WRITER.lock().set(&mut SEV_ES_SERIAL); }
}

#[no_mangle]
pub extern "C" fn stage2_main() {
	setup_env();
	print_heap_info();
	sev_init();

	let fw_cfg = FwCfg::new(&SEV_ES_IO);

	if let Err(_e) = fw_cfg.read_e820() {
		println!("Failed to read E820 table from fw_cfg");
	}
	dump_cpuid_table();

	panic!("Road ends here!");
}

#[panic_handler]
fn panic(info : &PanicInfo) -> ! {
	println!("Panic: {}", info);
	loop { halt(); }
}
