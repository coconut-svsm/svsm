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
pub mod svsm_paging;
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

pub mod fw_meta;
use fw_meta::parse_fw_meta_data;

use mm::alloc::{memory_init, memory_info, print_memory_info};
use cpu::percpu::{PerCpu, register_per_cpu, load_per_cpu};
use sev::secrets_page::{SecretsPage, copy_secrets_page};
use svsm_paging::{init_page_table, invalidate_stage2};
use mm::stack::{allocate_stack, stack_base_pointer};
use crate::cpu::control_regs::{cr0_init, cr4_init};
use cpu::cpuid::{SnpCpuidTable, copy_cpuid_table};
use cpu::idt::{early_idt_init, idt_init};
use acpi::tables::load_acpi_cpu_info;
use console::{WRITER, init_console};
use crate::svsm_console::SVSMIOPort;
use kernel_launch::KernelLaunchInfo;
use core::arch::{global_asm, asm};
use crate::cpu::efer::efer_init;
use mm::pagetable::paging_init;
use crate::serial::SERIAL_PORT;
use crate::serial::SerialPort;
use core::panic::PanicInfo;
use sev::utils::{RMPFlags};
use cpu::gdt::load_gdt;
use crate::util::halt;
use types::VirtAddr;
use fw_cfg::FwCfg;
use crate::sev::vmsa::VMSA;
use cpu::vmsa::init_svsm_vmsa;

pub use svsm_paging::{allocate_pt_page, virt_to_phys, phys_to_virt,
                      map_page_shared, map_page_encrypted, map_data_4k,
                      unmap_4k, walk_addr, INIT_PGTABLE, PTMappingGuard};

pub use cpu::percpu::{this_cpu, this_cpu_mut};

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

pub static mut PERCPU : PerCpu = PerCpu::new();

fn init_percpu() {
    unsafe {
        register_per_cpu(0, &PERCPU);
        PERCPU.setup().expect("Failed to setup percpu data");
        load_per_cpu(0);
    }
}

static CONSOLE_IO : SVSMIOPort = SVSMIOPort::new();
static mut CONSOLE_SERIAL : SerialPort = SerialPort { driver : &CONSOLE_IO, port : SERIAL_PORT };

pub fn boot_stack_info() {
    unsafe {
        let vaddr = (&bsp_stack_end as *const u8) as VirtAddr;
        println!("Boot stack starts        @ {:#018x}", vaddr);
    }
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

    this_cpu_mut().alloc_vmsa(RMPFlags::VMPL0).expect("Failed to allocate VMSA page");
    init_svsm_vmsa(this_cpu_mut().vmsa(RMPFlags::VMPL0));

    println!("BSP Runtime stack starts @ {:#018x}", bp);

    let rip = (svsm_main as extern "C" fn()) as u64;
    let rsp = stack_base_pointer(stack) as u64;

    this_cpu_mut().prepare_svsm_vmsa(rip, rsp);
    let sev_features = this_cpu_mut().vmsa(RMPFlags::VMPL0).sev_features;

    let vmsa_addr : VirtAddr = (this_cpu_mut().vmsa(RMPFlags::VMPL0) as *const VMSA) as VirtAddr;
    let vmsa_pa = virt_to_phys(vmsa_addr);

    println!("VMSA vaddr : {:#018x} paddr : {:#018x}", vmsa_addr, vmsa_pa);


    this_cpu_mut().ghcb().ap_create(vmsa_pa, 0, 0, sev_features).expect("Failed to load boot CPU VMSA");

    // Enable runtime stack and jump to main function
    unsafe {
        asm!("movq  %rax, %rsp
              jmp   svsm_main",
              in("rax") stack_base_pointer(stack),
              options(att_syntax));
    }
}

#[no_mangle]
pub extern "C" fn svsm_main() {

    invalidate_stage2().expect("Failed to invalidate Stage2 memory");

    let fw_cfg = FwCfg::new(&CONSOLE_IO);

	let cpus = load_acpi_cpu_info(&fw_cfg).expect("Failed to load ACPI tables");
    let mut nr_cpus = 0;

    for i in 0..cpus.size() {
        if cpus[i].enabled { nr_cpus += 1; }
    }

    println!("{} CPU(s) present", nr_cpus);

    let _ = parse_fw_meta_data();

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
