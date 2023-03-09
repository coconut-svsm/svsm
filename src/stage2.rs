// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

#![no_std]
#![no_main]
#![feature(const_mut_refs, rustc_private)]

pub mod boot_stage2;

extern crate compiler_builtins;
use core::arch::asm;
use core::panic::PanicInfo;
use log;
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::cpuid::{register_cpuid_table, SnpCpuidTable};
use svsm::cpu::msr;
use svsm::cpu::percpu::{this_cpu_mut, PerCpu};
use svsm::fw_cfg::{FwCfg, MemoryRegion};
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::init_kernel_mapping_info;
use svsm::mm::pagetable::{
    get_init_pgtable_locked, paging_init, paging_init_early, set_init_pgtable, PTEntryFlags,
    PageTable, PageTableRef,
};
use svsm::mm::validate::{init_valid_bitmap_alloc, valid_bitmap_addr, valid_bitmap_set_valid_2m};
use svsm::serial::{SerialPort, DEFAULT_SERIAL_PORT, SERIAL_PORT};
use svsm::sev::ghcb::PageStateChangeOp;
use svsm::sev::msr_protocol::GHCBMsr;
use svsm::sev::status::SEVStatusFlags;
use svsm::sev::{pvalidate_range, sev_status_init, sev_status_verify};
use svsm::svsm_console::SVSMIOPort;
use svsm::types::{PhysAddr, VirtAddr, PAGE_SIZE, PAGE_SIZE_2M};
use svsm::utils::{halt, is_aligned, page_align, page_align_up};

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

extern "C" {
    pub fn rdmsr_safe(msr: u32, dst: *mut u64) -> i64;
    pub fn wrmsr_safe(msr: u32, val: u64) -> i64;
    pub fn vmgexit_safe() -> i64;
}

// For use at an early stage when it's neither known yet that the GHCB MSR is
// valid (and thus, accesses can #GP) nor that the HV is implementing the GHCB
// MSR protocol on it.
fn ghcb_msr_proto_safe(cmd: u64) -> Result<u64, ()> {
    let mut orig_msr_val: u64 = 0;
    if unsafe { rdmsr_safe(msr::SEV_GHCB, &mut orig_msr_val as *mut u64) } != 0 {
        return Err(());
    }

    if unsafe { wrmsr_safe(msr::SEV_GHCB, cmd) } != 0 {
        return Err(());
    }

    if unsafe { vmgexit_safe() } != 0 {
        unsafe { wrmsr_safe(msr::SEV_GHCB, orig_msr_val) };
        return Err(());
    }

    let mut response: u64 = 0;
    let r = unsafe { rdmsr_safe(msr::SEV_GHCB, &mut response as *mut u64) };
    unsafe { wrmsr_safe(msr::SEV_GHCB, orig_msr_val) };
    if r != 0 {
        return Err(());
    }

    Ok(response)
}

// Check that the SEV_STATUS and GHCB MSRs are present and behaving as expected.
// In particular, it's being verified that the HV respnds properly to the GHCB
// MSR protocol. Returns the (untrusted!) PTE C-bit position as a byproduct on
// success.
fn sev_ghcb_msr_available() -> Result<u64, ()> {
    // First check: the SEV_STATUS MSR should be present and indicate that
    // either SEV_ES or SEV_SNP is active.
    let mut status_raw: u64 = 0;
    if unsafe { rdmsr_safe(msr::SEV_STATUS, &mut status_raw) } != 0 {
        return Err(());
    }

    let status = SEVStatusFlags::from_bits_truncate(status_raw);
    if !status.contains(SEVStatusFlags::SEV_ES) && !status.contains(SEVStatusFlags::SEV_SNP) {
        return Err(());
    }

    // Second check: the GHCB MSR should be present and the HV should respond
    // to GHCB MSR protocol info requests.
    let sev_info = match ghcb_msr_proto_safe(GHCBMsr::SEV_INFO_REQ) {
        Ok(info) => info,
        Err(_) => return Err(()),
    };

    if sev_info & 0xfffu64 != GHCBMsr::SEV_INFO_RESP {
        return Err(());
    }

    // Compare announced supported GHCB MSR protocol version range
    // for compatibility.
    let min_version = (sev_info >> 32) & 0xffffu64;
    let max_version = (sev_info >> 48) & 0xffffu64;
    if min_version > 2 || max_version < 1 {
        return Err(());
    }

    // Retrieve the PTE C-bit position and check its range.
    let c_bit_pos = sev_info >> 24 & 0x3fu64;
    if c_bit_pos < 32 || c_bit_pos >= 64 {
        return Err(());
    }

    let encrypt_mask: u64 = 1u64 << c_bit_pos;
    Ok(encrypt_mask)
}

fn setup_env() {
    install_console_logger("Stage2");
    init_kernel_mapping_info(0, 640 * 1024, 0);

    // Under SVM-ES, the only means to communicate with the user is through the
    // SVSMIOPort console, which requires a functional GHCB protocol. If the
    // GHCB is not available, indicating that SEV-ES is probably not active, the
    // last resort is to print an error to the standard serial using emulated io
    // insns and hope that it reaches the user. If SEV-ES is enabled, the
    // SVSMIOPort needs the GHCB initialized, which in turn requires the paging
    // subsystem to be in a tentative working state.
    match sev_ghcb_msr_available() {
        Ok(encrypt_mask) => paging_init_early(encrypt_mask),
        Err(_) => {
            unsafe {
                DEFAULT_SERIAL_PORT.init();
            }
            init_console();
            panic!("SEV-ES not available");
        }
    };

    // Bring up the GCHB for use from the SVSMIOPort console.
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
    sev_status_verify();

    // At this point, SEV-SNP is confirmed. Register the supplied CPUID page.
    register_cpuid_table(unsafe { &CPUID_PAGE });

    // At this point SEV-SNP is confirmed to be active and the CPUID table
    // should be available. Fully initialize the paging subsystem now. In
    // particular this verifies that the C-bit from the CPUID table matches what
    // has been obtained above.
    paging_init();
}

fn map_kernel_region(vaddr: VirtAddr, region: &MemoryRegion) -> Result<(), ()> {
    let flags = PTEntryFlags::PRESENT
        | PTEntryFlags::WRITABLE
        | PTEntryFlags::ACCESSED
        | PTEntryFlags::DIRTY;
    let paddr = region.start as PhysAddr;
    let size = (region.end - region.start) as usize;

    let mut pgtbl = get_init_pgtable_locked();

    log::info!(
        "Mapping kernel region {:#018x}-{:#018x} to {:#018x}",
        vaddr,
        vaddr + size,
        paddr
    );

    pgtbl.map_region_2m(vaddr, vaddr + size, paddr, flags)
}

fn validate_kernel_region(vaddr: VirtAddr, region: &MemoryRegion) -> Result<(), ()> {
    let pstart = region.start as PhysAddr;
    let pend = region.end as PhysAddr;
    let size: usize = pend - pstart;

    assert!(is_aligned(pstart, PAGE_SIZE_2M));
    assert!(is_aligned(pend, PAGE_SIZE_2M));

    this_cpu_mut()
        .ghcb()
        .page_state_change(pstart, pend, true, PageStateChangeOp::PscPrivate)
        .expect("GHCB::PAGE_STATE_CHANGE call failed for kernel region");

    pvalidate_range(vaddr, vaddr + size, true).expect("PVALIDATE kernel region failed");

    for paddr in (pstart..pend).step_by(PAGE_SIZE_2M) {
        valid_bitmap_set_valid_2m(paddr);
    }

    Ok(())
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
    let kernel_launch_info = KernelLaunchInfo {
        kernel_start: kli.phys_base as u64,
        kernel_end: kli.phys_end as u64,
        virt_base: kli.virt_base as u64,
        cpuid_page: 0x9f000u64,
        secrets_page: 0x9e000u64,
        ghcb: 0,
    };

    log::info!(
        "  kernel_physical_start = {:#018x}",
        kernel_launch_info.kernel_start
    );
    log::info!(
        "  kernel_physical_end   = {:#018x}",
        kernel_launch_info.kernel_end
    );
    log::info!(
        "  kernel_virtual_base   = {:#018x}",
        kernel_launch_info.virt_base
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

    map_kernel_region(kernel_virt_base, &r).expect("Error mapping kernel region");
    validate_kernel_region(kernel_virt_base, &r).expect("Validating kernel region failed");

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
