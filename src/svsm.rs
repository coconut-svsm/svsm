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
pub mod svsm_paging;

use svsm::fw_meta::{parse_fw_meta_data, validate_fw_memory, print_fw_meta, SevFWMetaData};

use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::efer::efer_init;
use svsm::serial::SerialPort;
use svsm::serial::SERIAL_PORT;
use svsm::svsm_console::SVSMIOPort;
use svsm::utils::{halt, immut_after_init::ImmutAfterInitCell};
use svsm::acpi::tables::load_acpi_cpu_info;
use svsm::console::{init_console, install_console_logger, WRITER};
use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use svsm::cpu::cpuid::{register_cpuid_table, SnpCpuidTable};
use svsm::cpu::gdt::load_gdt;
use svsm::cpu::idt::{early_idt_init, idt_init};
use svsm::cpu::percpu::PerCpu;
use svsm::fw_cfg::FwCfg;
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm::{SVSM_SHARED_BASE, SIZE_1G};
use svsm::mm::alloc::{memory_info, root_mem_init, print_memory_info, virt_to_phys};
use svsm::mm::pagetable::{paging_init, PTMappingGuard};
use svsm::mm::memory::init_memory_map;
use svsm::sev::secrets_page::{copy_secrets_page, SecretsPage};
use svsm_paging::{init_page_table, invalidate_stage2};
use svsm::types::{VirtAddr, PhysAddr, PAGE_SIZE};
use svsm::cpu::percpu::{this_cpu_mut, this_cpu};
use svsm::sev::sev_status_init;
use svsm::sev::vmsa::{VMSA};
use svsm::sev::utils::{rmp_adjust, RMPFlags};
use svsm::requests::request_loop;

use core::ptr;

use log;

extern "C" {
    pub static mut SECRETS_PAGE: SecretsPage;
    pub static bsp_stack_end: u8;
}

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %r8  will contain a pointer to the KernelLaunchInfo structure
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code64

        .globl  startup_64
    startup_64:
        /* Clear BSS */
        xorq    %rax, %rax
        leaq    sbss(%rip), %rdi
        leaq    ebss(%rip), %rcx
        subq    %rdi, %rcx
        shrq    $3, %rcx
        rep stosq

        /* Setup stack */
        leaq bsp_stack_end(%rip), %rsp

        /* Jump to rust code */
        movq    %r8, %rdi
        jmp svsm_start

        .bss

        .align 4096
    bsp_stack:
        .fill 8192, 1, 0
    bsp_stack_end:

        .align 4096
        .globl SECRETS_PAGE
    SECRETS_PAGE:
        .fill 4096, 1, 0
        "#,
    options(att_syntax)
);

extern "C" {
    static _stext: u8;
    static _etext: u8;
    static _sdata: u8;
    static _edata: u8;
    static _sdataro: u8;
    static _edataro: u8;
    static _sbss: u8;
    static _ebss: u8;
    pub static heap_start: u8;
}

static CPUID_PAGE: ImmutAfterInitCell<SnpCpuidTable> = ImmutAfterInitCell::uninit();
static LAUNCH_INFO: ImmutAfterInitCell<KernelLaunchInfo> = ImmutAfterInitCell::uninit();

pub static mut PERCPU: PerCpu = PerCpu::new();

fn copy_cpuid_table_to_fw(fw_addr : PhysAddr) -> Result<(), ()> {
	let start = (SVSM_SHARED_BASE + (128 * SIZE_1G)) as VirtAddr;
    let end   = start + PAGE_SIZE;
    let guard = PTMappingGuard::create(start, end, fw_addr);

    guard.check_mapping()?;

    let target = ptr::NonNull::new(start as *mut SnpCpuidTable).unwrap();

    // Zero target
    unsafe {
        let mut page_ptr = target.cast::<u8>();
        ptr::write_bytes(page_ptr.as_mut(), 0, PAGE_SIZE);
    }

    // Copy data
    unsafe {
        let dst = target.as_ptr();
        *dst = *CPUID_PAGE;
    }

    Ok(())
}

fn copy_secrets_page_to_fw(fw_addr : PhysAddr, caa_addr : PhysAddr) -> Result<(), ()> {
	let start = (SVSM_SHARED_BASE + (128 * SIZE_1G)) as VirtAddr;
    let end   = start + PAGE_SIZE;
    let guard = PTMappingGuard::create(start, end, fw_addr);

    guard.check_mapping()?;

    let mut target = ptr::NonNull::new(start as *mut SecretsPage).unwrap();

    // Zero target
    unsafe {
        let mut page_ptr = target.cast::<u8>();
        ptr::write_bytes(page_ptr.as_mut(), 0, PAGE_SIZE);
    }

    // Copy and initialize data
    unsafe {
        let dst = target.as_ptr();
        *dst = SECRETS_PAGE;

        // Copy Table
        let mut fw_sp = target.as_mut();

        // Zero VMCK0 key
        for i in 0..32 {
            fw_sp.vmpck0[i] = 0;
        }

        let &li = &*LAUNCH_INFO;

        fw_sp.svsm_base = li.kernel_start;
        fw_sp.svsm_size = li.kernel_end - li.kernel_start;
        fw_sp.svsm_caa  = caa_addr as u64;
        fw_sp.svsm_max_version = 1;
        fw_sp.svsm_guest_vmpl = 1;
    }

    Ok(())
}

fn zero_caa_page(fw_addr : PhysAddr) -> Result<(), ()> {
	let start = (SVSM_SHARED_BASE + (128 * SIZE_1G)) as VirtAddr;
    let end   = start + PAGE_SIZE;
    let guard = PTMappingGuard::create(start, end, fw_addr);

    guard.check_mapping()?;

    let target = ptr::NonNull::new(start as *mut u8).unwrap();

    // Zero target
    unsafe {
        let mut page_ptr = target.cast::<u8>();
        ptr::write_bytes(page_ptr.as_mut(), 0, PAGE_SIZE);
    }

    Ok(())
}

pub fn copy_tables_to_fw(fw_meta : &SevFWMetaData) -> Result<(), ()> {

    let cpuid_page = match fw_meta.cpuid_page {
        Some(addr) => addr,
        None => panic!("FW does not specify CPUID_PAGE location"),
    };

    copy_cpuid_table_to_fw(cpuid_page)?;

    let secrets_page = match fw_meta.secrets_page {
        Some(addr) => addr,
        None => panic!("FW does not specify SECRETS_PAGE location"),
    };

    let caa_page = match fw_meta.caa_page  {
        Some(addr) => addr,
        None => panic!("FW does not specify CAA_PAGE location"),
    };

    copy_secrets_page_to_fw(secrets_page, caa_page)?;

    zero_caa_page(caa_page)
}

fn setup_caa(fw_meta: &SevFWMetaData) -> Result<(),()> {
    let addr = fw_meta.caa_page.unwrap();

    this_cpu_mut().map_caa_phys(addr)
}

fn prepare_fw_launch() -> Result<(), ()>
{
    let cpu = this_cpu_mut();

    cpu.alloc_vmsa(1)?;
    cpu.prepare_guest_vmsa()?;

    Ok(())
}

fn launch_fw() -> Result<(),()> {
    let cpu = this_cpu_mut();

    let vmsa_addr = (cpu.vmsa(1) as *const VMSA) as VirtAddr;
    let vmsa_pa = virt_to_phys(vmsa_addr);
    let sev_features = cpu.vmsa(1).sev_features;

    log::info!("Launching Firmware");
    cpu.vmsa(1).enable();
    cpu.ghcb().ap_create(vmsa_pa, 0, 1, sev_features)?;

    Ok(())
}

fn validate_flash() -> Result<(),()> {
    let fw_cfg = FwCfg::new(&CONSOLE_IO);
    let count = fw_cfg.flash_region_count();

    for i in 0..count {
        let flash = fw_cfg.get_flash_region(i)?;
        log::info!("Flash region {} at {:#018x} size {:018x}", i, flash.start, flash.end - flash.start);

        let start = (SVSM_SHARED_BASE + (128 * SIZE_1G)) as VirtAddr;
        let len:usize = (flash.end - flash.start) as usize;
        let end   = (start + len) as VirtAddr;
        let pstart = flash.start as PhysAddr;
        let guard = PTMappingGuard::create(start, end, pstart);

        guard.check_mapping()?;

        let mut current = start;
        while  current < end {
            if let Err(_) = rmp_adjust(current, RMPFlags::VMPL1_RWX, false) {
                log::info!("rmpadjust failed for addr {:#018x}", current);
                return Err(());
            }
            current += PAGE_SIZE;
        }
    }

    Ok(())
}

pub fn memory_init(launch_info: &KernelLaunchInfo) {
    let mem_size = launch_info.kernel_end - launch_info.kernel_start;
    let vstart = unsafe { (&heap_start as *const u8) as VirtAddr };
    let vend = (launch_info.virt_base + mem_size) as VirtAddr;
    let page_count = (vend - vstart) / PAGE_SIZE;
    let heap_offset = vstart - launch_info.virt_base as VirtAddr;
    let pstart = launch_info.kernel_start as PhysAddr + heap_offset;

    root_mem_init(pstart, vstart, page_count);
}

static CONSOLE_IO: SVSMIOPort = SVSMIOPort::new();
static mut CONSOLE_SERIAL: SerialPort = SerialPort {
    driver: &CONSOLE_IO,
    port: SERIAL_PORT,
};

pub fn boot_stack_info() {
    unsafe {
        let vaddr = (&bsp_stack_end as *const u8) as VirtAddr;
        log::info!("Boot stack starts        @ {:#018x}", vaddr);
    }
}

#[no_mangle]
pub extern "C" fn svsm_start(li: &KernelLaunchInfo) {
    let launch_info: KernelLaunchInfo = *li;

    load_gdt();
    early_idt_init();

    unsafe { LAUNCH_INFO.init(li); }

    let cpuid_table_virt = launch_info.cpuid_page as VirtAddr;
    unsafe { CPUID_PAGE.init(&*(cpuid_table_virt as *const SnpCpuidTable)) };
    register_cpuid_table(&CPUID_PAGE);

    unsafe {
        let secrets_page_virt = launch_info.secrets_page as VirtAddr;
        copy_secrets_page(&mut SECRETS_PAGE, secrets_page_virt);
    }

    cr0_init();
    cr4_init();
    efer_init();
    sev_status_init();

    memory_init(&launch_info);
    paging_init();
    init_page_table(&launch_info);

    unsafe {
        let bsp_percpu = PerCpu::alloc()
            .expect("Failed to allocate BSP per-cpu data")
            .as_mut()
            .unwrap();

        bsp_percpu.setup().expect("Failed to setup BSP per-cpu area");
        bsp_percpu.load();
    }
    idt_init();

    unsafe {
        WRITER.lock().set(&mut CONSOLE_SERIAL);
    }
    init_console();
    install_console_logger("SVSM");

    log::info!("Secure Virtual Machine Service Module (SVSM)");

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    boot_stack_info();

    let bp = this_cpu().get_top_of_stack();

    log::info!("BSP Runtime stack starts @ {:#018x}", bp);

    // Enable runtime stack and jump to main function
    unsafe {
        asm!("movq  %rax, %rsp
              jmp   svsm_main",
              in("rax") bp,
              options(att_syntax));
    }
}

#[no_mangle]
pub extern "C" fn svsm_main() {
    invalidate_stage2().expect("Failed to invalidate Stage2 memory");

    let fw_cfg = FwCfg::new(&CONSOLE_IO);

    init_memory_map(&fw_cfg, &LAUNCH_INFO).expect("Failed to init guest memory map");

    let cpus = load_acpi_cpu_info(&fw_cfg).expect("Failed to load ACPI tables");
    let mut nr_cpus = 0;

    for i in 0..cpus.len() {
        if cpus[i].enabled {
            nr_cpus += 1;
        }
    }

    log::info!("{} CPU(s) present", nr_cpus);

    let fw_meta = parse_fw_meta_data().expect("Failed to parse FW SEV meta-data");
    
    print_fw_meta(&fw_meta);

    validate_fw_memory(&fw_meta).expect("Failed to validate firmware memory");

    copy_tables_to_fw(&fw_meta).expect("Failed to copy firmware tables");

    setup_caa(&fw_meta).expect("Failed to setup CAA for BSP");

    validate_flash().expect("Failed to validate flash memory");

    prepare_fw_launch().expect("Failed to setup guest VMSA");

    launch_fw().expect("Failed to launch FW");

    request_loop();

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("Panic: {}", info);
    loop {
        halt();
    }
}
