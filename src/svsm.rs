#![no_std]
#![no_main]

pub mod kernel_launch;
pub mod locking;
pub mod types;
pub mod util;
pub mod cpu;
pub mod mm;

use crate::cpu::control_regs::{cr0_init, cr4_init};
use cpu::cpuid::{SnpCpuidTable, copy_cpuid_table};
use mm::pagetable::{paging_init, PageTable};
use kernel_launch::KernelLaunchInfo;
use crate::cpu::efer::efer_init;
use types::{VirtAddr, PhysAddr};
use core::panic::PanicInfo;
use core::arch::{global_asm};
use mm::alloc::memory_init;
use cpu::gdt::load_gdt;
use cpu::idt::idt_init;
use locking::SpinLock;
use core::ptr;
use core::fmt;

#[macro_use]
extern crate bitflags;

extern "C" {
	pub static mut CPUID_PAGE : SnpCpuidTable;
}

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %rdx will contain the offset from the phys->virt offset
 * %r8  will contain a pointer to the KernelLaunchInfo structure
 */
global_asm!(r#"
		.text
		.section ".startup.text","ax"
		.code64
		.quad	0xffffff8000000000
		.quad	startup_64
		
		.org	0x80

		.globl	startup_64
	startup_64:
		/* Save PHYS_OFFSET */
		movq	%rdx, PHYS_OFFSET(%rip)

		/* Setup stack */
		leaq bsp_stack_end(%rip), %rsp

		/* Clear BSS */
		xorq	%rax, %rax
		leaq	sbss(%rip), %rdi
		leaq	ebss(%rip), %rcx
		subq	%rdi, %rcx
		shrq	$3, %rcx
		rep stosq

		/* Jump to rust code */
		movq	%r8, %rdi
		jmp	svsm_main
		
		.data

		.globl PHYS_OFFSET
	PHYS_OFFSET:
		.quad 0

		.align 4096
	bsp_stack:
		.fill 4096, 1, 0
	bsp_stack_end:

		.bss

		.align 4096
		.globl CPUID_PAGE
	CPUID_PAGE:
		.fill 4096, 1, 0

		.align 4096
		.globl SECRETS_PAGE
	SECRETS_PAGE:
		.fill 4096, 1, 0
		"#, options(att_syntax));

extern "C" {
	pub static PHYS_OFFSET : u64;
	pub static heap_start : u8;
}

pub fn allocate_pt_page() -> *mut u8 {
	let pt_page : VirtAddr = mm::alloc::allocate_zeroed_page().expect("Failed to allocate pgtable page");

	pt_page as *mut u8
}

pub fn virt_to_phys(vaddr : VirtAddr) -> PhysAddr {
	mm::alloc::virt_to_phys(vaddr)
}

pub fn phys_to_virt(paddr : PhysAddr) -> VirtAddr {
	mm::alloc::phys_to_virt(paddr)
}

pub static INIT_PGTABLE : SpinLock<*mut PageTable> = SpinLock::new(ptr::null_mut());

extern "C" {
	static stext	: u8;
	static etext	: u8;
	static sdata	: u8;
	static edata	: u8;
	static sdataro	: u8;
	static edataro	: u8;
	static sbss	: u8;
	static ebss	: u8;
}

fn init_page_table(launch_info : &KernelLaunchInfo) {
	let vaddr = mm::alloc::allocate_zeroed_page().expect("Failed to allocate root page-table");
	let mut ptr = INIT_PGTABLE.lock();
	let offset = (launch_info.virt_base - launch_info.kernel_start) as usize;

	*ptr = vaddr as *mut PageTable;

	unsafe {
		let pgtable = ptr.as_mut().unwrap();

		/* Text segment */
		let start : VirtAddr = (&stext as *const u8) as VirtAddr;
		let end   : VirtAddr = (&etext as *const u8) as VirtAddr;
		let phys  : PhysAddr = start - offset;

		(*pgtable).map_region_4k(start, end, phys, PageTable::exec_flags()).expect("Failed to map text segment");

		/* Writeble data */
		let start : VirtAddr = (&sdata as *const u8) as VirtAddr;
		let end   : VirtAddr = (&edata as *const u8) as VirtAddr;
		let phys  : PhysAddr = start - offset;

		(*pgtable).map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map data segment");

		/* Read-only data */
		let start : VirtAddr = (&sdataro as *const u8) as VirtAddr;
		let end   : VirtAddr = (&edataro as *const u8) as VirtAddr;
		let phys  : PhysAddr = start - offset;

		(*pgtable).map_region_4k(start, end, phys, PageTable::data_ro_flags()).expect("Failed to map read-only data");

		/* BSS */
		let start : VirtAddr = (&sbss as *const u8) as VirtAddr;
		let end   : VirtAddr = (&ebss as *const u8) as VirtAddr;
		let phys  : PhysAddr = start - offset;

		(*pgtable).map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map bss segment");

		/* Heap */
		let start : VirtAddr = (&heap_start as *const u8) as VirtAddr;
		let end   : VirtAddr = (launch_info.kernel_end as VirtAddr) + offset;
		let phys  : PhysAddr = start - offset;

		(*pgtable).map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map heap");

		(*pgtable).load();
	}
}

#[no_mangle]
pub extern "C" fn svsm_main(launch_info : &KernelLaunchInfo) {

	load_gdt();
	idt_init();
	cr0_init();
	cr4_init();
	efer_init();

	unsafe {
		let cpuid_table_virt = launch_info.cpuid_page as VirtAddr;
		copy_cpuid_table(&mut CPUID_PAGE, cpuid_table_virt);
	}

	paging_init();
	memory_init(&launch_info);
	init_page_table(&launch_info);


	panic!("Road ends here!");
}

#[panic_handler]
fn panic(_info : &PanicInfo) -> ! {
	loop { }
}

#[macro_export]
macro_rules! print {
	($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
	() => ($crate::print!("\n"));
	($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(_args: fmt::Arguments) {
	// Empty for now
}
