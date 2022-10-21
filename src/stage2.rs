// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

#![no_std]
#![no_main]
#![feature(const_mut_refs,rustc_private)]

pub mod kernel_launch;
pub mod svsm_console;
pub mod boot_stage2;
pub mod locking;
pub mod console;
pub mod string;
pub mod serial;
pub mod fw_cfg;
pub mod cpu;
pub mod types;
pub mod util;
pub mod sev;
pub mod io;
pub mod mm;

extern crate compiler_builtins;
use mm::alloc::{root_mem_init, memory_info, ALLOCATOR, print_memory_info};
use serial::{DEFAULT_SERIAL_PORT, SERIAL_PORT, SerialPort};
use mm::pagetable::{PageTable, PTEntryFlags, paging_init};
use sev::{sev_init, sev_es_enabled, pvalidate};
use util::{page_align, page_align_up, halt};
use types::{VirtAddr, PhysAddr, PAGE_SIZE};
use sev::msr_protocol::validate_page_msr;
use kernel_launch::KernelLaunchInfo;
use crate::svsm_console::SVSMIOPort;
use console::{WRITER, init_console};
use fw_cfg::{FwCfg, KernelRegion};
use core::alloc::GlobalAlloc;
use core::panic::PanicInfo;
use cpu::cpuid::SnpCpuidTable;
use core::alloc::Layout;
use cpu::percpu::PerCpu;
use core::arch::asm;

#[macro_use]
extern crate bitflags;

extern "C" {
    pub static heap_start: u8;
    pub static heap_end: u8;
    pub static mut pgtable : PageTable;
    pub static CPUID_PAGE : SnpCpuidTable;
}

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

pub fn map_page_shared(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe { pgtable.set_shared_4k(vaddr) }
}

pub fn map_page_encrypted(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe { pgtable.set_encrypted_4k(vaddr) }
}

pub fn map_data_4k(vaddr : VirtAddr, paddr : PhysAddr) -> Result<(), ()> {
    unsafe {
        let flags = PageTable::data_flags();
        pgtable.map_4k(vaddr, paddr, &flags)
    }
}

pub fn unmap_4k(vaddr : VirtAddr) -> Result<(), ()> {
    unsafe { pgtable.unmap_4k(vaddr) }
}

pub fn walk_addr(vaddr : VirtAddr) -> Result<PhysAddr, ()> {
    unsafe { pgtable.phys_addr(vaddr) }
}

fn setup_stage2_allocator() {
    let vstart   = unsafe { page_align_up((&heap_start as *const u8) as VirtAddr) };
    let vend     = unsafe { page_align((&heap_end as *const u8) as VirtAddr) };
    let pstart   = virt_to_phys(vstart);
    let nr_pages = (vend - vstart) / PAGE_SIZE;

    root_mem_init(pstart, vstart, nr_pages);
}

pub static mut PERCPU : PerCpu = PerCpu::new();

fn init_percpu() {
    unsafe {
        PERCPU.setup_ghcb().expect("Failed to setup percpu data");
        PERCPU.set_gs_base();
    }
}

fn shutdown_percpu() {
    unsafe { PERCPU.shutdown().expect("Failed to shut down percpu data (including GHCB)"); }
}

static CONSOLE_IO : SVSMIOPort = SVSMIOPort::new();
static mut CONSOLE_SERIAL : SerialPort = SerialPort { driver : &CONSOLE_IO, port : SERIAL_PORT };

fn setup_env() {
    sev_init();
    setup_stage2_allocator();
    init_percpu();

    if !sev_es_enabled() {
        unsafe { DEFAULT_SERIAL_PORT.init(); }
        panic!("SEV-ES not available");
    }

    unsafe { WRITER.lock().set(&mut CONSOLE_SERIAL); }
    init_console();
}

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

fn map_kernel_region(vaddr: VirtAddr, region : &KernelRegion) -> Result<(),()> {
    let paddr = region.start as PhysAddr;
    let pend = region.end as PhysAddr;

    map_memory(paddr, pend, vaddr)
}

fn validate_kernel_region(mut vaddr: VirtAddr, region : &KernelRegion) -> Result<(), ()> {
    let mut paddr = region.start as PhysAddr;
    let pend  = region.end as PhysAddr;

    loop {

        if let Err(_e) = validate_page_msr(paddr) {
            println!("Error: Validating page failed for physical address {:#018x}", paddr);
            return Err(());
        }

        if let Err(_e) = pvalidate(vaddr, false, true) {
            println!("Error: PVALIDATE failed for virtual address {:#018x}", vaddr);
            return Err(());
        }

        vaddr += 4096;
        paddr += 4096;

        if paddr >= pend {
            break;
        }
    }

    Ok(())
}


#[repr(C, packed)]
struct KernelMetaData {
    virt_addr   : VirtAddr,
    entry       : VirtAddr,
}

struct KInfo {
    k_image_start : PhysAddr,
    k_image_end   : PhysAddr,
    phys_base     : PhysAddr,
    phys_end      : PhysAddr,
    virt_base     : VirtAddr,
    entry         : VirtAddr,
}

unsafe fn copy_and_launch_kernel(kli : KInfo) {
    let image_size = kli.k_image_end - kli.k_image_start;
    let phys_offset = kli.virt_base - kli.phys_base;
    let kernel_launch_info = KernelLaunchInfo {
        kernel_start : kli.phys_base as u64,
        kernel_end   : kli.phys_end  as u64,
        virt_base    : kli.virt_base as u64,
        cpuid_page   : 0x9f000u64,
        secrets_page : 0x9e000u64,
        ghcb         : 0,
    };

    println!("  kernel_physical_start = {:#018x}", kernel_launch_info.kernel_start);
    println!("  kernel_physical_end   = {:#018x}", kernel_launch_info.kernel_end);
    println!("  kernel_virtual_base   = {:#018x}", kernel_launch_info.virt_base);
    println!("  cpuid_page            = {:#018x}", kernel_launch_info.cpuid_page);
    println!("  secrets_page          = {:#018x}", kernel_launch_info.secrets_page);
    println!("Launching SVSM kernel...");

    // Shut down the GHCB
    shutdown_percpu();

    compiler_builtins::mem::memcpy(kli.virt_base as *mut u8,
                                   kli.k_image_start as *const u8,
                                   image_size);
    asm!("jmp *%rax",
          in("rax") kli.entry,
          in("rdx") phys_offset,
          in("r8") &kernel_launch_info,
          options(att_syntax));
}

#[no_mangle]
pub extern "C" fn stage2_main(kernel_start : PhysAddr, kernel_end : PhysAddr) {
    paging_init();
    setup_env();
    sev_init();

    let fw_cfg = FwCfg::new(&CONSOLE_IO);

    let r = fw_cfg.find_kernel_region().unwrap();

    println!("Secure Virtual Machine Service Module (SVSM) Stage 2 Loader");

    let (kernel_virt_base, kernel_entry) = unsafe {
        let kmd : *const KernelMetaData =  kernel_start as *const KernelMetaData;
        ((*kmd).virt_addr, (*kmd).entry)
    };

    map_kernel_region(kernel_virt_base, &r).expect("Error mapping kernel region");
    validate_kernel_region(kernel_virt_base, &r).expect("Validating kernel region failed");

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    unsafe {
        copy_and_launch_kernel( KInfo {
                        k_image_start   : kernel_start,
                        k_image_end : kernel_end,
                        phys_base   : r.start as usize,
                        phys_end    : r.end as usize,
                        virt_base   : kernel_virt_base,
                        entry       : kernel_entry } );
        // This should never return
    }

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
    ($($arg:tt)*) => ($crate::print!("[Stage2] {}\n", format_args!($($arg)*)));
}
