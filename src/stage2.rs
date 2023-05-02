// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]
#![feature(const_mut_refs, rustc_private)]

pub mod boot_stage2;

use core::arch::asm;
use core::panic::PanicInfo;
use core::slice;
use log;
use svsm::address::{Address, PhysAddr, VirtAddr};
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table, SnpCpuidTable};
use svsm::cpu::percpu::{this_cpu_mut, PerCpu};
use svsm::elf;
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
use svsm::types::PAGE_SIZE;
use svsm::utils::halt;

extern "C" {
    pub static heap_start: u8;
    pub static heap_end: u8;
    pub static mut pgtable: PageTable;
    pub static CPUID_PAGE: SnpCpuidTable;
}

fn setup_stage2_allocator() {
    let vstart = unsafe { VirtAddr::from(&heap_start as *const u8).page_align_up() };
    let vend = unsafe { VirtAddr::from(&heap_end as *const u8).page_align() };
    let pstart = PhysAddr::from(vstart.bits()); // Identity mapping
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
    init_kernel_mapping_info(
        VirtAddr::null(),
        VirtAddr::from(640 * 1024 as usize),
        PhysAddr::null(),
    );
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
        .map_region(vaddr, vaddr.offset(len), paddr, flags)
        .expect("Error mapping kernel region");

    this_cpu_mut()
        .ghcb()
        .page_state_change(
            paddr,
            paddr.offset(len),
            true,
            PageStateChangeOp::PscPrivate,
        )
        .expect("GHCB::PAGE_STATE_CHANGE call failed for kernel region");
    pvalidate_range(vaddr, vaddr.offset(len), true).expect("PVALIDATE kernel region failed");
    valid_bitmap_set_valid_range(paddr, paddr.offset(len));
}

#[no_mangle]
pub extern "C" fn stage2_main(kernel_elf_start: PhysAddr, kernel_elf_end: PhysAddr) {
    setup_env();

    // Find a suitable physical memory region to allocate to the SVSM kernel.
    let fw_cfg = FwCfg::new(&CONSOLE_IO);
    let r = fw_cfg
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    log::info!("COCONUT Secure Virtual Machine Service Module (SVSM) Stage 2 Loader");

    let kernel_region_phys_start = PhysAddr::from(r.start);
    let kernel_region_phys_end = PhysAddr::from(r.end);
    init_valid_bitmap_alloc(kernel_region_phys_start, kernel_region_phys_end)
        .expect("Failed to allocate valid-bitmap");

    // Read the SVSM kernel's ELF file metadata.
    let kernel_elf_len = kernel_elf_end - kernel_elf_start;
    let kernel_elf_buf =
        unsafe { slice::from_raw_parts(kernel_elf_start.bits() as *const u8, kernel_elf_len) };
    let kernel_elf = match elf::Elf64File::read(kernel_elf_buf) {
        Ok(kernel_elf) => kernel_elf,
        Err(e) => panic!("error reading kernel ELF: {}", e),
    };

    let kernel_vaddr_alloc_info = kernel_elf.image_load_vaddr_alloc_info();
    let kernel_vaddr_alloc_base = kernel_vaddr_alloc_info.range.vaddr_begin;

    // Map, validate and populate the SVSM kernel ELF's PT_LOAD segments. The
    // segments' virtual address range might not necessarily be contiguous,
    // track their total extent along the way. Physical memory is successively
    // being taken from the physical memory region, the remaining space will be
    // available as heap space for the SVSM kernel. Remember the end of all
    // physical memory occupied by the loaded ELF image.
    let mut loaded_kernel_virt_start: Option<VirtAddr> = None;
    let mut loaded_kernel_virt_end = VirtAddr::null();
    let mut loaded_kernel_phys_end = PhysAddr::from(kernel_region_phys_start);
    for segment in kernel_elf.image_load_segment_iter(kernel_vaddr_alloc_base) {
        // All ELF segments should be aligned to the page size. If not, there's
        // the risk of pvalidating a page twice, bail out if so. Note that the
        // ELF reading code had already verified that the individual segments,
        // with bounds specified as in the ELF file, are non-overlapping.
        let vaddr_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
        if !vaddr_start.is_page_aligned() {
            panic!("kernel ELF segment not aligned to page boundary");
        }

        // Remember the mapping range's lower bound to pass it on the kernel
        // later. Note that the segments are being iterated over here in
        // increasing load order.
        if loaded_kernel_virt_start.is_none() {
            loaded_kernel_virt_start = Some(vaddr_start);
        }

        let vaddr_end = VirtAddr::from(segment.vaddr_range.vaddr_end);
        let aligned_vaddr_end = vaddr_end.page_align_up();
        loaded_kernel_virt_end = aligned_vaddr_end;

        let segment_len = aligned_vaddr_end - vaddr_start;
        let paddr_start = loaded_kernel_phys_end;
        loaded_kernel_phys_end = loaded_kernel_phys_end.offset(segment_len);

        map_and_validate(vaddr_start, paddr_start, segment_len);

        let segment_buf =
            unsafe { slice::from_raw_parts_mut(vaddr_start.as_mut_ptr::<u8>(), segment_len) };
        let segment_contents = segment.file_contents;
        let contents_len = segment_contents.len();
        segment_buf[..contents_len].copy_from_slice(segment_contents);
        segment_buf[contents_len..].fill(0);
    }

    let loaded_kernel_virt_start = match loaded_kernel_virt_start {
        Some(loaded_kernel_virt_start) => loaded_kernel_virt_start,
        None => {
            panic!("no loadable segment found in kernel ELF");
        }
    };

    // Apply relocations, if any.
    let dyn_relocs = match kernel_elf
        .apply_dyn_relas(elf::Elf64X86RelocProcessor::new(), kernel_vaddr_alloc_base)
    {
        Ok(dyn_relocs) => dyn_relocs,
        Err(e) => {
            panic!("failed to read ELF relocations : {}", e);
        }
    };
    if let Some(dyn_relocs) = dyn_relocs {
        for reloc in dyn_relocs {
            let reloc = match reloc {
                Ok(Some(reloc)) => reloc,
                Ok(None) => continue,
                Err(e) => {
                    panic!("ELF relocation error: {}", e);
                }
            };
            let dst = unsafe { slice::from_raw_parts_mut(reloc.dst as *mut u8, reloc.value_len) };
            let src = &reloc.value[..reloc.value_len];
            dst.copy_from_slice(src)
        }
    }

    // Map the rest of the memory region to right after the kernel image.
    let heap_area_phys_start = loaded_kernel_phys_end;
    let heap_area_virt_start = loaded_kernel_virt_end;
    let heap_area_size = kernel_region_phys_end - heap_area_phys_start;
    map_and_validate(heap_area_virt_start, heap_area_phys_start, heap_area_size);

    // Build the handover information describing the memory layout and hand
    // control to the SVSM kernel.
    let launch_info = KernelLaunchInfo {
        kernel_region_phys_start: u64::from(kernel_region_phys_start),
        kernel_region_phys_end: u64::from(kernel_region_phys_end),
        heap_area_phys_start: u64::from(heap_area_phys_start),
        kernel_region_virt_start: u64::from(loaded_kernel_virt_start),
        heap_area_virt_start: u64::from(heap_area_virt_start),
        kernel_elf_stage2_virt_start: u64::from(kernel_elf_start),
        kernel_elf_stage2_virt_end: u64::from(kernel_elf_end),
        cpuid_page: 0x9f000u64,
        secrets_page: 0x9e000u64,
    };

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    log::info!(
        "  kernel_region_phys_start = {:#018x}",
        kernel_region_phys_start
    );
    log::info!(
        "  kernel_region_phys_end   = {:#018x}",
        kernel_region_phys_end
    );
    log::info!(
        "  kernel_virtual_base   = {:#018x}",
        loaded_kernel_virt_start
    );

    let kernel_entry = kernel_elf.get_entry(kernel_vaddr_alloc_base);
    let valid_bitmap = valid_bitmap_addr();

    // Shut down the GHCB
    shutdown_percpu();

    unsafe {
        asm!("jmp *%rax",
             in("rax") kernel_entry,
             in("r8") &launch_info,
             in("r9") valid_bitmap.bits(),
             options(att_syntax))
    };

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("Panic: {}", info);
    loop {
        halt();
    }
}
