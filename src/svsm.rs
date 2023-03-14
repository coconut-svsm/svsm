// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]
#![feature(const_mut_refs)]
pub mod svsm_paging;

use svsm::fw_meta::{parse_fw_meta_data, print_fw_meta, validate_fw_memory, SevFWMetaData};

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use svsm::acpi::tables::load_acpi_cpu_info;
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::cpuid::{register_cpuid_table, SnpCpuidTable};
use svsm::cpu::efer::efer_init;
use svsm::cpu::gdt::load_gdt;
use svsm::cpu::idt::{early_idt_init, idt_init};
use svsm::cpu::percpu::PerCpu;
use svsm::cpu::percpu::{this_cpu, this_cpu_mut};
use svsm::cpu::smp::start_secondary_cpus;
use svsm::debug::stacktrace::print_stack;
use svsm::fw_cfg::FwCfg;
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::memory::init_memory_map;
use svsm::mm::pagetable::paging_init;
use svsm::mm::{init_kernel_mapping_info, PerCPUPageMappingGuard};
use svsm::requests::{request_loop, update_mappings};
use svsm::serial::SerialPort;
use svsm::serial::SERIAL_PORT;
use svsm::sev::secrets_page::{copy_secrets_page, SecretsPage};
use svsm::sev::sev_status_init;
use svsm::sev::utils::{rmp_adjust, RMPFlags};
use svsm::svsm_console::SVSMIOPort;
use svsm::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use svsm::utils::{halt, immut_after_init::ImmutAfterInitCell, zero_mem_region};
use svsm_paging::{init_page_table, invalidate_stage2};

use svsm::mm::validate::{init_valid_bitmap_ptr, migrate_valid_bitmap};

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
 * %r8  Pointer to the KernelLaunchInfo structure
 * %r9  Pointer to the valid-bitmap from stage2
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code64

        .globl  startup_64
    startup_64:
        /* Setup stack */
        leaq bsp_stack_end(%rip), %rsp

        /* Jump to rust code */
        movq    %r8, %rdi
        movq    %r9, %rsi
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
}

static CPUID_PAGE: ImmutAfterInitCell<SnpCpuidTable> = ImmutAfterInitCell::uninit();
static LAUNCH_INFO: ImmutAfterInitCell<KernelLaunchInfo> = ImmutAfterInitCell::uninit();

pub static mut PERCPU: PerCpu = PerCpu::new();

fn copy_cpuid_table_to_fw(fw_addr: PhysAddr) -> Result<(), ()> {
    let guard = PerCPUPageMappingGuard::create(fw_addr, 0, false)?;
    let start = guard.virt_addr();
    let end = start + PAGE_SIZE;

    let target = ptr::NonNull::new(start as *mut SnpCpuidTable).unwrap();

    // Zero target
    zero_mem_region(start, end);

    // Copy data
    unsafe {
        let dst = target.as_ptr();
        *dst = *CPUID_PAGE;
    }

    Ok(())
}

fn copy_secrets_page_to_fw(fw_addr: PhysAddr, caa_addr: PhysAddr) -> Result<(), ()> {
    let guard = PerCPUPageMappingGuard::create(fw_addr, 0, false)?;
    let start = guard.virt_addr();

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

        fw_sp.svsm_base = li.kernel_region_phys_start;
        fw_sp.svsm_size = li.kernel_region_phys_end - li.kernel_region_phys_start;
        fw_sp.svsm_caa = caa_addr as u64;
        fw_sp.svsm_max_version = 1;
        fw_sp.svsm_guest_vmpl = 1;
    }

    Ok(())
}

fn zero_caa_page(fw_addr: PhysAddr) -> Result<(), ()> {
    let guard = PerCPUPageMappingGuard::create(fw_addr, 0, false)?;
    let vaddr = guard.virt_addr();

    zero_mem_region(vaddr, vaddr + PAGE_SIZE);

    Ok(())
}

pub fn copy_tables_to_fw(fw_meta: &SevFWMetaData) -> Result<(), ()> {
    let cpuid_page = match fw_meta.cpuid_page {
        Some(addr) => addr,
        None => panic!("FW does not specify CPUID_PAGE location"),
    };

    copy_cpuid_table_to_fw(cpuid_page)?;

    let secrets_page = match fw_meta.secrets_page {
        Some(addr) => addr,
        None => panic!("FW does not specify SECRETS_PAGE location"),
    };

    let caa_page = match fw_meta.caa_page {
        Some(addr) => addr,
        None => panic!("FW does not specify CAA_PAGE location"),
    };

    copy_secrets_page_to_fw(secrets_page, caa_page)?;

    zero_caa_page(caa_page)
}

fn prepare_fw_launch(fw_meta: &SevFWMetaData) -> Result<(), ()> {
    let caa = fw_meta.caa_page.unwrap();
    let cpu = this_cpu_mut();

    cpu.alloc_guest_vmsa()?;
    cpu.update_guest_caa(caa);
    update_mappings()?;

    Ok(())
}

fn launch_fw() -> Result<(), ()> {
    let vmsa_pa = this_cpu_mut().guest_vmsa_ref().vmsa_phys().unwrap();
    let vmsa = this_cpu_mut().guest_vmsa();

    log::info!("VMSA PA: {:#x}", vmsa_pa);

    vmsa.enable();
    let sev_features = vmsa.sev_features;

    log::info!("Launching Firmware");
    this_cpu_mut()
        .ghcb()
        .ap_create(vmsa_pa, 0, 1, sev_features)?;

    Ok(())
}

fn validate_flash() -> Result<(), ()> {
    let mut fw_cfg = FwCfg::new(&CONSOLE_IO);

    for (i, region) in fw_cfg.iter_flash_regions().enumerate() {
        let pstart = region.start as PhysAddr;
        let pend = region.end as PhysAddr;
        log::info!(
            "Flash region {} at {:#018x} size {:018x}",
            i,
            pstart,
            pend - pstart
        );

        for paddr in (pstart..pend).step_by(PAGE_SIZE) {
            let guard = PerCPUPageMappingGuard::create(paddr, 0, false)?;
            let vaddr = guard.virt_addr();
            if let Err(_) = rmp_adjust(vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, false) {
                log::info!("rmpadjust failed for addr {:#018x}", vaddr);
                return Err(());
            }
        }
    }

    Ok(())
}

pub fn memory_init(launch_info: &KernelLaunchInfo) {
    root_mem_init(
        launch_info.heap_area_phys_start as PhysAddr,
        launch_info.heap_area_virt_start as VirtAddr,
        launch_info.heap_area_size() as usize / PAGE_SIZE,
    );
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

fn mapping_info_init(launch_info: &KernelLaunchInfo) {
    init_kernel_mapping_info(
        launch_info.heap_area_virt_start as VirtAddr,
        launch_info.heap_area_virt_end() as VirtAddr,
        launch_info.heap_area_phys_start as PhysAddr,
    );
}

#[no_mangle]
pub extern "C" fn svsm_start(li: &KernelLaunchInfo, vb_addr: VirtAddr) {
    let launch_info: KernelLaunchInfo = *li;
    let vb_ptr = vb_addr as *mut u64;

    mapping_info_init(&launch_info);

    init_valid_bitmap_ptr(
        launch_info.kernel_region_phys_start.try_into().unwrap(),
        launch_info.kernel_region_phys_end.try_into().unwrap(),
        vb_ptr,
    );

    load_gdt();
    early_idt_init();

    unsafe {
        LAUNCH_INFO.init(li);
    }

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
    migrate_valid_bitmap().expect("Failed to migrate valid-bitmap");

    paging_init();
    init_page_table(&launch_info);

    unsafe {
        let bsp_percpu = PerCpu::alloc(0)
            .expect("Failed to allocate BSP per-cpu data")
            .as_mut()
            .unwrap();

        bsp_percpu
            .setup()
            .expect("Failed to setup BSP per-cpu area");
        bsp_percpu
            .setup_on_cpu()
            .expect("Failed to run percpu.setup_on_cpu()");
        bsp_percpu.load();
    }
    idt_init();

    unsafe {
        WRITER.lock().set(&mut CONSOLE_SERIAL);
    }
    init_console();
    install_console_logger("SVSM");

    log::info!("COCONUT Secure Virtual Machine Service Module (SVSM)");

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

    for cpu in cpus.iter() {
        if cpu.enabled {
            nr_cpus += 1;
        }
    }

    log::info!("{} CPU(s) present", nr_cpus);

    start_secondary_cpus(&cpus);

    let fw_meta = parse_fw_meta_data().expect("Failed to parse FW SEV meta-data");

    print_fw_meta(&fw_meta);

    validate_fw_memory(&fw_meta).expect("Failed to validate firmware memory");

    copy_tables_to_fw(&fw_meta).expect("Failed to copy firmware tables");

    validate_flash().expect("Failed to validate flash memory");

    prepare_fw_launch(&fw_meta).expect("Failed to setup guest VMSA");

    launch_fw().expect("Failed to launch FW");

    request_loop();

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("Panic: CPU[{}] {}", this_cpu().get_apic_id(), info);

    print_stack(3);

    loop {
        halt();
    }
}
