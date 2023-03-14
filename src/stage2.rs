// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]
#![feature(const_mut_refs, rustc_private)]

pub mod boot_stage2;

extern crate compiler_builtins;
use core::arch::asm;
use core::panic::PanicInfo;
use log;
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table, SnpCpuidTable};
use svsm::cpu::percpu::{this_cpu_mut, PerCpu};
use svsm::fw_cfg::FwCfg;
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::init_kernel_mapping_info;
use svsm::mm::pagetable::{
    get_init_pgtable_locked, paging_init_early, set_init_pgtable, PTEntryFlags, PageTable,
    PageTableRef,
};
use svsm::mm::validate::{
    init_valid_bitmap_alloc, valid_bitmap_addr, valid_bitmap_set_valid_range,
};
use svsm::serial::{SerialPort, SERIAL_PORT};
use svsm::sev::ghcb::PageStateChangeOp;
use svsm::sev::msr_protocol::verify_ghcb_version;
use svsm::sev::{pvalidate_range, sev_status_init, sev_status_verify};
use svsm::svsm_console::SVSMIOPort;
use svsm::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use svsm::utils::{halt, page_align, page_align_up};

extern "C" {
    pub static heap_start: u8;
    pub static heap_end: u8;
    pub static mut pgtable: PageTable;
    pub static CPUID_PAGE: SnpCpuidTable;
}

fn setup_stage2_allocator() {
    let vstart = unsafe { page_align_up((&heap_start as *const u8) as VirtAddr) };
    let vend = unsafe { page_align((&heap_end as *const u8) as VirtAddr) };
    let pstart = vstart as PhysAddr; // Identity mapping
    let nr_pages = (vend - vstart) / PAGE_SIZE;

    root_mem_init(pstart, vstart, nr_pages);
}

pub static mut PERCPU: PerCpu = PerCpu::new();

fn init_percpu() {
    unsafe {
        let bsp_percpu = PerCpu::alloc(0)
            .expect("Failed to allocate BSP per-cpu data")
            .as_mut()
            .unwrap();

        bsp_percpu.set_pgtable(PageTableRef::new(&mut pgtable));
        bsp_percpu.map_self().expect("Failed to map per-cpu area");
        bsp_percpu.setup_ghcb().expect("Failed to setup BSP GHCB");
        bsp_percpu.register_ghcb().expect("Failed to register GHCB");
    }
}

fn shutdown_percpu() {
    unsafe {
        PERCPU
            .shutdown()
            .expect("Failed to shut down percpu data (including GHCB)");
    }
}

static CONSOLE_IO: SVSMIOPort = SVSMIOPort::new();
static mut CONSOLE_SERIAL: SerialPort = SerialPort {
    driver: &CONSOLE_IO,
    port: SERIAL_PORT,
};

fn setup_env() {
    install_console_logger("Stage2");
    init_kernel_mapping_info(0, 640 * 1024, 0);
    register_cpuid_table(unsafe { &CPUID_PAGE });
    paging_init_early();

    // Bring up the GCHB for use from the SVSMIOPort console.
    verify_ghcb_version();
    sev_status_init();
    set_init_pgtable(PageTableRef::new(unsafe { &mut pgtable }));
    setup_stage2_allocator();
    init_percpu();

    unsafe {
        WRITER.lock().set(&mut CONSOLE_SERIAL);
    }
    init_console();

    // Console is fully working now and any unsupported configuration can be
    // properly reported.
    dump_cpuid_table();
    sev_status_verify();
}

fn map_and_validate(vaddr: VirtAddr, paddr: PhysAddr, len: usize) {
    let flags = PTEntryFlags::PRESENT
        | PTEntryFlags::WRITABLE
        | PTEntryFlags::ACCESSED
        | PTEntryFlags::DIRTY;

    let mut pgtbl = get_init_pgtable_locked();
    pgtbl
        .map_region(vaddr, vaddr + len, paddr, flags)
        .expect("Error mapping kernel region");

    this_cpu_mut()
        .ghcb()
        .page_state_change(paddr, paddr + len, true, PageStateChangeOp::PscPrivate)
        .expect("GHCB::PAGE_STATE_CHANGE call failed for kernel region");
    pvalidate_range(vaddr, vaddr + len, true).expect("PVALIDATE kernel region failed");
    valid_bitmap_set_valid_range(paddr, paddr + len);
}

#[repr(C, packed)]
struct KernelMetaData {
    virt_addr: VirtAddr,
    entry: VirtAddr,
}

struct KInfo {
    k_image_start: PhysAddr,
    k_image_end: PhysAddr,
    phys_base: PhysAddr,
    phys_end: PhysAddr,
    virt_base: VirtAddr,
    entry: VirtAddr,
}

unsafe fn copy_and_launch_kernel(kli: KInfo) {
    let image_size = kli.k_image_end - kli.k_image_start;
    let heap_offset = page_align_up(image_size as usize) as u64;
    let kernel_region_phys_start = kli.phys_base as u64;
    let kernel_region_phys_end = kli.phys_end as u64;
    let kernel_region_virt_start = kli.virt_base as u64;
    let heap_area_phys_start = kernel_region_phys_start + heap_offset;
    let heap_area_virt_start = kernel_region_virt_start + heap_offset;
    let kernel_launch_info = KernelLaunchInfo {
        kernel_region_phys_start,
        kernel_region_phys_end,
        heap_area_phys_start,
        kernel_region_virt_start,
        heap_area_virt_start,
        cpuid_page: 0x9f000u64,
        secrets_page: 0x9e000u64,
    };

    log::info!(
        "  kernel_physical_start = {:#018x}",
        kernel_launch_info.kernel_region_phys_start
    );
    log::info!(
        "  kernel_physical_end   = {:#018x}",
        kernel_launch_info.kernel_region_phys_end
    );
    log::info!(
        "  kernel_virtual_base   = {:#018x}",
        kernel_launch_info.kernel_region_virt_start
    );
    log::info!(
        "  cpuid_page            = {:#018x}",
        kernel_launch_info.cpuid_page
    );
    log::info!(
        "  secrets_page          = {:#018x}",
        kernel_launch_info.secrets_page
    );
    log::info!("Launching SVSM kernel...");

    // Shut down the GHCB
    shutdown_percpu();

    let valid_bitmap: PhysAddr = valid_bitmap_addr();

    compiler_builtins::mem::memcpy(
        kli.virt_base as *mut u8,
        kli.k_image_start as *const u8,
        image_size,
    );
    asm!("jmp *%rax",
          in("rax") kli.entry,
          in("r8") &kernel_launch_info,
          in("r9") valid_bitmap,
          options(att_syntax));
}

#[no_mangle]
pub extern "C" fn stage2_main(kernel_start: PhysAddr, kernel_end: PhysAddr) {
    setup_env();

    let fw_cfg = FwCfg::new(&CONSOLE_IO);
    let r = fw_cfg
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    log::info!("COCONUT Secure Virtual Machine Service Module (SVSM) Stage 2 Loader");

    let (kernel_virt_base, kernel_entry) = unsafe {
        let kmd: *const KernelMetaData = kernel_start as *const KernelMetaData;
        ((*kmd).virt_addr, (*kmd).entry)
    };

    init_valid_bitmap_alloc(r.start.try_into().unwrap(), r.end.try_into().unwrap())
        .expect("Failed to allocate valid-bitmap");

    log::info!(
        "Mapping kernel region {:#018x}-{:#018x} to {:#018x}",
        kernel_virt_base,
        kernel_virt_base + (r.end - r.start) as usize,
        r.start as PhysAddr
    );
    map_and_validate(
        kernel_virt_base,
        r.start as PhysAddr,
        (r.end - r.start) as usize,
    );

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    unsafe {
        copy_and_launch_kernel(KInfo {
            k_image_start: kernel_start,
            k_image_end: kernel_end,
            phys_base: r.start as usize,
            phys_end: r.end as usize,
            virt_base: kernel_virt_base,
            entry: kernel_entry,
        });
        // This should never return
    }

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("Panic: {}", info);
    loop {
        halt();
    }
}
