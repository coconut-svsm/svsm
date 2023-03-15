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
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::cpuid::{register_cpuid_table, SnpCpuidTable};
use svsm::cpu::msr;
use svsm::cpu::percpu::{this_cpu_mut, PerCpu};
use svsm::elf;
use svsm::fw_cfg::FwCfg;
use svsm::kernel_launch::KernelLaunchInfo;
use svsm::mm::address_space::{SVSM_SHARED_BASE, SVSM_SHARED_STACK_BASE};
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::init_kernel_mapping_info;
use svsm::mm::pagetable::{
    get_init_pgtable_locked, paging_init, paging_init_early, set_init_pgtable, PTEntryFlags,
    PageTable, PageTableRef,
};
use svsm::mm::validate::{
    init_valid_bitmap_alloc, valid_bitmap_addr, valid_bitmap_set_valid_range,
};
use svsm::serial::{SerialPort, DEFAULT_SERIAL_PORT, SERIAL_PORT};
use svsm::sev::ghcb::PageStateChangeOp;
use svsm::sev::msr_protocol::GHCBMsr;
use svsm::sev::status::SEVStatusFlags;
use svsm::sev::{pvalidate_range, sev_status_init, sev_status_verify};
use svsm::svsm_console::SVSMIOPort;
use svsm::types::{PhysAddr, VirtAddr, PAGE_SIZE, PAGE_SIZE_2M};
use svsm::utils::{halt, is_aligned, page_align, page_align_up, rdrand64};

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

#[no_mangle]
pub extern "C" fn stage2_main(kernel_elf_start: PhysAddr, kernel_elf_end: PhysAddr) {
    setup_env();

    // Find a suitable physical memory region to allocate to the SVSM kernel.
    let fw_cfg = FwCfg::new(&CONSOLE_IO);
    let r = fw_cfg
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    log::info!("COCONUT Secure Virtual Machine Service Module (SVSM) Stage 2 Loader");

    let (kernel_region_phys_start, kernel_region_phys_end) = (r.start as usize, r.end as usize);
    init_valid_bitmap_alloc(kernel_region_phys_start, kernel_region_phys_end)
        .expect("Failed to allocate valid-bitmap");

    // Read the SVSM kernel's ELF file metadata.
    let kernel_elf_len = (kernel_elf_end - kernel_elf_start) as usize;
    let kernel_elf_buf =
        unsafe { slice::from_raw_parts(kernel_elf_start as *const u8, kernel_elf_len) };
    let kernel_elf = match elf::Elf64File::read(kernel_elf_buf) {
        Ok(kernel_elf) => kernel_elf,
        Err(e) => panic!("error reading kernel ELF: {}", e),
    };

    // Find a suitable load base for the ELF.
    let kernel_vaddr_alloc_info = kernel_elf.image_load_vaddr_alloc_info();
    let kernel_vaddr_alloc_base = match kernel_vaddr_alloc_info.align {
        Some(align) => {
            // Virtual address alignment constraints given, it's a
            // PIE. Randomize the virtual base address. Enforce page alignment
            // at minimum.
            let align = (align as usize).max(PAGE_SIZE);

            // The image will get loaded anywhere between SVMS_SHARED_BASE and
            // SVSM_SHARED_STACK_BASE.
            // Reject addresses that would not leave enough room towards the
            // stack area for mapping the SVSM kernel itself and the remainder
            // of the physical memory region made available as a heap. In
            // reality, the heap will not span the whole physical region,
            // because the heading part of the latter will be allocated to the
            // loaded kernel, but compute the worst case virtual mapping extents
            // for simplicity.
            let max_heap_mapping_size = kernel_region_phys_end - kernel_region_phys_start;

            // The first ELF segment's virtual starting address is not
            // necessarily aligned. Compute the excess space at the head due to the
            // alignment operation on the virtual base and add it to the maximum
            // mapping size.
            let kernel_mapping_align_op_excess =
                kernel_vaddr_alloc_info.range.vaddr_begin as usize & (align - 1);
            let kernel_mapping_extents = kernel_mapping_align_op_excess
                + page_align_up(kernel_vaddr_alloc_info.range.len() as usize);
            let max_virt_mapping_extents = max_heap_mapping_size + kernel_mapping_extents;

            if max_virt_mapping_extents > SVSM_SHARED_STACK_BASE {
                panic!("Not enough virtual address space room for SVSM kernel mapping.");
            }

            let mut retries = 10;
            loop {
                if retries == 0 {
                    panic!("Maximum number of SVSM kernel address space randomization retries exceeded.");
                }
                retries -= 1;

                let rand = match rdrand64() {
                    Some(rand) => rand as usize,
                    None => continue,
                };
                if rand == 0 {
                    continue;
                }
                let load_offset = rand % (SVSM_SHARED_STACK_BASE - SVSM_SHARED_BASE);
                let load_offset = load_offset & !(align - 1);
                let kernel_vaddr_alloc_base = SVSM_SHARED_BASE + load_offset;
                if kernel_vaddr_alloc_base > SVSM_SHARED_STACK_BASE - max_virt_mapping_extents {
                    continue;
                }
                break (kernel_vaddr_alloc_base + kernel_mapping_align_op_excess) as u64;
            }
        }
        None => kernel_vaddr_alloc_info.range.vaddr_begin,
    };

    // Map, validate and populate the SVSM kernel ELF's PT_LOAD segments. The
    // segments' virtual address range might not necessarily be contiguous,
    // track their total extent along the way. Physical memory is successively
    // being taken from the physical memory region, the remaining space will be
    // available as heap space for the SVSM kernel. Remember the end of all
    // physical memory occupied by the loaded ELF image.
    let mut loaded_kernel_virt_start: Option<VirtAddr> = None;
    let mut loaded_kernel_virt_end: VirtAddr = 0;
    let mut loaded_kernel_phys_end = kernel_region_phys_start as PhysAddr;
    for segment in kernel_elf.image_load_segment_iter(kernel_vaddr_alloc_base) {
        // All ELF segments should be aligned to the page size. If not, there's
        // the risk of pvalidating a page twice, bail out if so. Note that the
        // ELF reading code had already verified that the individual segments,
        // with bounds specified as in the ELF file, are non-overlapping.
        let vaddr_start = segment.vaddr_range.vaddr_begin as VirtAddr;
        if !is_aligned(vaddr_start, PAGE_SIZE) {
            panic!("kernel ELF segment not aligned to page boundary");
        }

        // Remember the mapping range's lower bound to pass it on the kernel
        // later. Note that the segments are being iterated over here in
        // increasing load order.
        if loaded_kernel_virt_start.is_none() {
            loaded_kernel_virt_start = Some(vaddr_start);
        }

        let vaddr_end = segment.vaddr_range.vaddr_end as VirtAddr;
        let aligned_vaddr_end = page_align_up(vaddr_end);
        loaded_kernel_virt_end = aligned_vaddr_end;

        let segment_len = aligned_vaddr_end - vaddr_start;
        let paddr_start = loaded_kernel_phys_end;
        loaded_kernel_phys_end += segment_len;

        map_and_validate(vaddr_start, paddr_start, segment_len);

        let segment_buf = unsafe { slice::from_raw_parts_mut(vaddr_start as *mut u8, segment_len) };
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

    // Map the rest of the memory region to right after the kernel image. To
    // facilitate mapping as 2MB pages, make sure the virtual and physical
    // addresses are congruent modulo 2MB.
    let heap_area_phys_start = loaded_kernel_phys_end;
    let mut heap_area_virt_start = (loaded_kernel_virt_end & !(PAGE_SIZE_2M - 1))
        + (heap_area_phys_start & (PAGE_SIZE_2M - 1));
    if heap_area_virt_start < loaded_kernel_virt_end {
        heap_area_virt_start += PAGE_SIZE_2M;
    }
    let heap_area_size = kernel_region_phys_end - heap_area_phys_start;
    map_and_validate(heap_area_virt_start, heap_area_phys_start, heap_area_size);

    // Build the handover information describing the memory layout and hand
    // control to the SVSM kernel.
    let launch_info = KernelLaunchInfo {
        kernel_region_phys_start: kernel_region_phys_start as u64,
        kernel_region_phys_end: kernel_region_phys_end as u64,
        heap_area_phys_start: heap_area_phys_start as u64,
        kernel_region_virt_start: loaded_kernel_virt_start as u64,
        heap_area_virt_start: heap_area_virt_start as u64,
        kernel_elf_stage2_virt_start: kernel_elf_start as u64,
        kernel_elf_stage2_virt_end: kernel_elf_end as u64,
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
    let valid_bitmap: PhysAddr = valid_bitmap_addr();

    // Shut down the GHCB
    shutdown_percpu();

    unsafe {
        asm!("jmp *%rax",
             in("rax") kernel_entry,
             in("r8") &launch_info,
             in("r9") valid_bitmap,
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
