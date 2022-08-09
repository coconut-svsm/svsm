// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

#![no_std]
#![no_main]

#![feature(const_mut_refs)]
pub mod kernel_launch;
pub mod svsm_console;
pub mod console;
pub mod locking;
pub mod string;
pub mod fw_cfg;
pub mod serial;
pub mod types;
pub mod acpi;
pub mod util;
pub mod lib;
pub mod cpu;
pub mod sev;
pub mod mm;
pub mod io;

use mm::alloc::{memory_init, memory_info, print_memory_info};
use sev::secrets_page::{SecretsPage, copy_secrets_page};
use mm::stack::{allocate_stack, stack_base_pointer};
use crate::cpu::control_regs::{cr0_init, cr4_init};
use cpu::cpuid::{SnpCpuidTable, copy_cpuid_table};
use mm::pagetable::{paging_init, PageTable};
use sev::msr_protocol::invalidate_page_msr;
use types::{VirtAddr, PhysAddr, PAGE_SIZE};
use cpu::idt::{early_idt_init, idt_init};
use acpi::tables::load_acpi_cpu_info;
use console::{WRITER, init_console};
use crate::svsm_console::SVSMIOPort;
use kernel_launch::KernelLaunchInfo;
use core::arch::{global_asm, asm};
use crate::cpu::efer::efer_init;
use crate::serial::SERIAL_PORT;
use crate::serial::SerialPort;
use core::panic::PanicInfo;
use cpu::percpu::PerCpu;
use cpu::gdt::load_gdt;
use crate::util::halt;
use locking::SpinLock;
use sev::pvalidate;
use fw_cfg::FwCfg;
use core::ptr;

#[macro_use]
extern crate bitflags;

extern "C" {
    pub static mut SECRETS_PAGE : SecretsPage;
    pub static mut CPUID_PAGE : SnpCpuidTable;
    pub static bsp_stack_end : u8;
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
        .quad   0xffffff8000000000
        .quad   startup_64
        
        .org    0x80

        .globl  startup_64
    startup_64:
        /* Save PHYS_OFFSET */
        movq    %rdx, PHYS_OFFSET(%rip)

        /* Setup stack */
        leaq bsp_stack_end(%rip), %rsp

        /* Clear BSS */
        xorq    %rax, %rax
        leaq    sbss(%rip), %rdi
        leaq    ebss(%rip), %rcx
        subq    %rdi, %rcx
        shrq    $3, %rcx
        rep stosq

        /* Jump to rust code */
        movq    %r8, %rdi
        jmp svsm_start
        
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

pub fn map_page_shared(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).set_shared_4k(vaddr)
    }
}

pub fn map_page_encrypted(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).set_encrypted_4k(vaddr)
    }
}

pub fn map_data_4k(vaddr : VirtAddr, paddr : PhysAddr) -> Result<(), ()> {
    unsafe {
        let ptr   = INIT_PGTABLE.lock().as_mut().unwrap();
        let flags = PageTable::data_flags();
        (*ptr).map_4k(vaddr, paddr, &flags)
    }
}

pub fn unmap_4k(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).unmap_4k(vaddr)
    }
}

pub fn walk_addr(vaddr : VirtAddr) -> Result<PhysAddr, ()> {
    unsafe {
        let ptr = INIT_PGTABLE.lock().as_mut().unwrap();
        (*ptr).phys_addr(vaddr)
    }
}

pub static INIT_PGTABLE : SpinLock<*mut PageTable> = SpinLock::new(ptr::null_mut());

extern "C" {
    static stext    : u8;
    static etext    : u8;
    static sdata    : u8;
    static edata    : u8;
    static sdataro  : u8;
    static edataro  : u8;
    static sbss : u8;
    static ebss : u8;
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

pub static mut PERCPU : PerCpu = PerCpu::new();

fn init_percpu() {
    unsafe { PERCPU.setup().expect("Failed to setup percpu data") }
}

static CONSOLE_IO : SVSMIOPort = SVSMIOPort::new();
static mut CONSOLE_SERIAL : SerialPort = SerialPort { driver : &CONSOLE_IO, port : SERIAL_PORT };

pub fn boot_stack_info() {
    unsafe {
        let vaddr = (&bsp_stack_end as *const u8) as VirtAddr;
        println!("Boot stack starts        @ {:#018x}", vaddr);
    }
}

fn invalidate_stage2() -> Result<(), ()> {
    let start : VirtAddr = 0;
    let end   : VirtAddr = 640 * 1024;
    let phys  : PhysAddr = 0;

    // Stage2 memory must be invalidated when already on the SVSM page-table,
    // because before that the stage2 page-table is still active, which is in
    // stage2 memory, causing invalidation of page-table pages.
    unsafe {
        INIT_PGTABLE.lock().as_mut().unwrap().map_region_4k(start, end, phys, PageTable::data_flags()).expect("Failed to map stage2 memory");
    }

    let mut curr = start;
    loop {
        if curr >= end { break; }

        pvalidate(curr, false, false).expect("PINVALIDATE failed");

        let paddr = curr as PhysAddr;
        invalidate_page_msr(paddr)?;

        curr += PAGE_SIZE;
    }

    // Done - Unmap stage2 memory
    unsafe {
        INIT_PGTABLE.lock().as_mut().unwrap().unmap_region_4k(start, end)?;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn svsm_start(li : &KernelLaunchInfo) {
    let launch_info : KernelLaunchInfo = *li;

    load_gdt();
    early_idt_init();

    unsafe {
        let cpuid_table_virt = launch_info.cpuid_page as VirtAddr;
        copy_cpuid_table(&mut CPUID_PAGE, cpuid_table_virt);

        let secrets_page_virt = launch_info.secrets_page as VirtAddr;
        copy_secrets_page(&mut SECRETS_PAGE, secrets_page_virt);
    }

    cr0_init();
    cr4_init();
    efer_init();

    memory_init(&launch_info);
    paging_init();
    init_page_table(&launch_info);

    init_percpu();
    idt_init();

    unsafe { WRITER.lock().set(&mut CONSOLE_SERIAL); }
    init_console();

    println!("Secure Virtual Machine Service Module (SVSM)");

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    boot_stack_info();

    let stack = allocate_stack().expect("Failed to allocate runtime stack");
    let bp = stack_base_pointer(stack);

    println!("BSP Runtime stack starts @ {:#018x}", bp);

    // Enable runtime stack and jump to main function
    unsafe {
        asm!("movq  %rax, %rsp
              jmp   svsm_main",
              in("rax") stack_base_pointer(stack),
              in("rdi") &launch_info,
              options(att_syntax));
    }
}

#[no_mangle]
pub extern "C" fn svsm_main(_launch_info : &KernelLaunchInfo) {

    invalidate_stage2().expect("Failed to invalidate Stage2 memory");

    let fw_cfg = FwCfg::new(&CONSOLE_IO);

	let cpus = load_acpi_cpu_info(&fw_cfg).expect("Failed to load ACPI tables");
    let mut nr_cpus = 0;

    for i in 0..cpus.size() {
        if cpus[i].enabled { nr_cpus += 1; }
    }

    println!("{} CPU(s) present", nr_cpus);

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info : &PanicInfo) -> ! {
    println!("Panic: {}", info);
    loop { halt(); }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("[SVSM] {}\n", format_args!($($arg)*)));
}
