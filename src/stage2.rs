#![no_std]
#![no_main]
#![feature(const_mut_refs)]

pub mod allocator_stage2;
pub mod kernel_launch;
pub mod boot_stage2;
pub mod pagetable;
pub mod locking;
pub mod console;
pub mod string;
pub mod serial;
pub mod fw_cfg;
pub mod cpuid;
pub mod types;
pub mod util;
pub mod msr;
pub mod sev;
pub mod io;

use sev::{GHCB, sev_status_init, sev_init, sev_es_enabled, validate_page_msr, pvalidate, GHCBIOPort};
use allocator_stage2::{Stage2Allocator, init_heap, print_heap_info};
use serial::{DEFAULT_SERIAL_PORT, SERIAL_PORT, SerialPort};
use types::{VirtAddr, PhysAddr, PAGE_SIZE};
use pagetable::{PageTable, PTEntryFlags};
use kernel_launch::KernelLaunchInfo;
use fw_cfg::{FwCfg, KernelRegion};
use core::alloc::GlobalAlloc;
use cpuid::dump_cpuid_table;
use core::panic::PanicInfo;
use core::cell::RefCell;
use core::alloc::Layout;
use locking::SpinLock;
use core::arch::asm;
use console::WRITER;
use util::halt;

#[macro_use]
extern crate bitflags;
extern crate memoffset;

#[global_allocator]
pub static ALLOCATOR: SpinLock<Stage2Allocator> = SpinLock::new(Stage2Allocator::new());

extern "C" {
	pub static mut pgtable : PageTable;
	pub static mut boot_ghcb : GHCB;
}

static SEV_ES_IO : GHCBIOPort = GHCBIOPort { ghcb : unsafe { RefCell::new(&mut boot_ghcb) } };
static mut SEV_ES_SERIAL : SerialPort = SerialPort { driver : &SEV_ES_IO, port : SERIAL_PORT };

pub fn allocate_pt_page() -> *mut u8 {
	let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();

	unsafe {
		let ptr = ALLOCATOR.alloc(layout);
		ptr as *mut u8
	}
}

pub fn virt_to_phys(vaddr : VirtAddr) -> PhysAddr {
	vaddr as PhysAddr
}

pub fn phys_to_virt(paddr : PhysAddr) -> VirtAddr {
	paddr as VirtAddr
}

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

const KERNEL_VIRT_ADDR : VirtAddr = 0xffff_ff80_0000_0000;

fn map_memory(mut paddr : PhysAddr, pend : PhysAddr, mut vaddr : VirtAddr) -> Result<(), ()> {
	let flags = PTEntryFlags::PRESENT | PTEntryFlags::WRITABLE | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY;

	loop {
		unsafe {
			if let Err(_e) = pgtable.map_4k(vaddr, paddr as PhysAddr, &flags) {
				return Err(());
			}
		}

		paddr += 4096;
		vaddr += 4096;

		if paddr >= pend {
			break;
		}
	}

	Ok(())
}

fn map_kernel_image(kernel_start : PhysAddr, kernel_end : PhysAddr) -> Result<(),()> {
	let vaddr = kernel_start as VirtAddr;
	let paddr = kernel_start;
	let pend = kernel_end;

	map_memory(paddr, pend, vaddr)
}

fn map_kernel_region(region : &KernelRegion) -> Result<(),()> {
	let kaddr = KERNEL_VIRT_ADDR;
	let paddr = region.start as PhysAddr;
	let pend = region.end as PhysAddr;

	map_memory(paddr, pend, kaddr)
}

fn validate_kernel_region(region : &KernelRegion) -> Result<(), ()> {
	let mut kaddr = KERNEL_VIRT_ADDR;
	let mut paddr = region.start as PhysAddr;
	let pend  = region.end as PhysAddr;

	loop {

		if let Err(_e) = validate_page_msr(paddr) {
			println!("Error: Validating page failed for physical address {:#018x}", paddr);
			return Err(());
		}

		if let Err(_e) = pvalidate(kaddr, false, true) {
			println!("Error: PVALIDATE failed for virtual address {:#018x}", kaddr);
			return Err(());
		}

		kaddr += 4096;
		paddr += 4096;

		if paddr >= pend {
			break;
		}
	}

	Ok(())
}


#[repr(C, packed)]
struct KernelMetaData {
	virt_addr	: VirtAddr,
	entry		: VirtAddr,
}

static mut KERNEL_LAUNCH_INFO : KernelLaunchInfo =  KernelLaunchInfo {
	kernel_start : 0,
	kernel_end : 0,
	virt_base : 0
};

unsafe fn copy_and_launch_kernel(kernel_start : PhysAddr, kernel_end : PhysAddr,
				 vaddr : VirtAddr, entry : VirtAddr) {

	let size = kernel_end - kernel_start;
	let phys_offset = vaddr - kernel_start;

	KERNEL_LAUNCH_INFO.kernel_start	= kernel_start as u64;
	KERNEL_LAUNCH_INFO.kernel_end	= kernel_end as u64;
	KERNEL_LAUNCH_INFO.virt_base	= vaddr as u64;

	asm!("cld
	      rep movsb
	      jmp *%rax",
	      in("rsi") kernel_start,
	      in("rdi") vaddr,
	      in("rcx") size,
	      in("rax") entry,
	      in("rdx") phys_offset,
	      in("r8") &KERNEL_LAUNCH_INFO,
	      options(att_syntax));
}

#[no_mangle]
pub extern "C" fn stage2_main(kernel_start : PhysAddr, kernel_end : PhysAddr) {
	setup_env();
	print_heap_info();
	sev_init();

	println!("Kernel start: {:#010x} end: {:#010x}", kernel_start, kernel_end);

	dump_cpuid_table();

	let fw_cfg = FwCfg::new(&SEV_ES_IO);

	let r = fw_cfg.find_kernel_region().unwrap();
	println!("Found kernel region, start: {:#08x} end: {:#08x}", r.start, r.end);

	match map_kernel_image(kernel_start, kernel_end) {
		Ok(()) => println!("Mapped kernel image"),
		Err(()) => println!("Mapping kernel image failed!"),
	}

	match map_kernel_region(&r) {
		Ok(())  => println!("Mapped kernel region to virtual address {:#018x}", KERNEL_VIRT_ADDR),
		Err(()) => println!("Error mapping kernel region"),
	}

	match validate_kernel_region(&r) {
		Ok(_e) => println!("Validated kernel region"),
		Err(_e) => println!("Validating kernel region failed"),
	}


	unsafe {
		let kmd : *const KernelMetaData = kernel_start as *const KernelMetaData;
		let vaddr = (*kmd).virt_addr as VirtAddr;
		let entry = (*kmd).entry as VirtAddr;

		println!("Kernel Image Virtual Address: {:#018x} Entry Point: {:#018x}", vaddr, entry);
		
		copy_and_launch_kernel(kernel_start, kernel_end, vaddr, entry);
		// This should never return
	}

	panic!("Road ends here!");
}

#[panic_handler]
fn panic(info : &PanicInfo) -> ! {
	println!("Panic: {}", info);
	loop { halt(); }
}
