// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

pub mod boot_stage2;

use bootlib::kernel_launch::{KernelLaunchInfo, Stage2LaunchInfo};
use bootlib::platform::SvsmPlatformType;
use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use svsm::address::{Address, PhysAddr, VirtAddr};
use svsm::config::SvsmConfig;
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::gdt;
use svsm::cpu::idt::stage2::{early_idt_init, early_idt_init_no_ghcb};
use svsm::cpu::percpu::{this_cpu_mut, PerCpu};
use svsm::fw_cfg::FwCfg;
use svsm::igvm_params::IgvmParams;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::init_kernel_mapping_info;
use svsm::mm::pagetable::{
    get_init_pgtable_locked, paging_init_early, set_init_pgtable, PTEntryFlags, PageTable,
    PageTableRef,
};
use svsm::mm::validate::{
    init_valid_bitmap_alloc, valid_bitmap_addr, valid_bitmap_set_valid_range,
};
use svsm::platform::{SvsmPlatform, SvsmPlatformCell};
use svsm::serial::SerialPort;
use svsm::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use svsm::utils::immut_after_init::ImmutAfterInitCell;
use svsm::utils::{halt, is_aligned, MemoryRegion};

extern "C" {
    pub static heap_start: u8;
    pub static heap_end: u8;
    pub static mut pgtable: PageTable;
    pub static CPUID_PAGE: SnpCpuidTable;
}

fn setup_stage2_allocator() {
    let vstart = unsafe { VirtAddr::from(addr_of!(heap_start)).page_align_up() };
    let vend = unsafe { VirtAddr::from(addr_of!(heap_end)).page_align() };
    let pstart = PhysAddr::from(vstart.bits()); // Identity mapping
    let nr_pages = (vend - vstart) / PAGE_SIZE;

    root_mem_init(pstart, vstart, nr_pages);
}

fn init_percpu(platform: &mut dyn SvsmPlatform) {
    let mut bsp_percpu = PerCpu::alloc(0).expect("Failed to allocate BSP per-cpu data");
    unsafe {
        bsp_percpu.set_pgtable(PageTableRef::shared(addr_of_mut!(pgtable)));
    }
    bsp_percpu
        .map_self_stage2()
        .expect("Failed to map per-cpu area");
    platform.setup_guest_host_comm(&mut bsp_percpu, true);
}

fn shutdown_percpu() {
    this_cpu_mut()
        .shutdown()
        .expect("Failed to shut down percpu data (including GHCB)");
}

static CONSOLE_SERIAL: ImmutAfterInitCell<SerialPort<'_>> = ImmutAfterInitCell::uninit();

fn setup_env(
    config: &SvsmConfig<'_>,
    platform: &mut dyn SvsmPlatform,
    launch_info: &Stage2LaunchInfo,
) {
    gdt().load();
    early_idt_init_no_ghcb();
    platform.env_setup();

    install_console_logger("Stage2");
    init_kernel_mapping_info(
        VirtAddr::null(),
        VirtAddr::from(640 * 1024usize),
        PhysAddr::null(),
    );
    register_cpuid_table(unsafe { &CPUID_PAGE });
    paging_init_early(platform, launch_info.vtom);

    set_init_pgtable(PageTableRef::shared(unsafe { addr_of_mut!(pgtable) }));
    setup_stage2_allocator();
    init_percpu(platform);

    // Init IDT again with handlers requiring GHCB (eg. #VC handler)
    early_idt_init();

    CONSOLE_SERIAL
        .init(&SerialPort {
            driver: platform.get_console_io_port(),
            port: config.debug_serial_port(),
        })
        .expect("console serial output already configured");
    (*CONSOLE_SERIAL).init();

    WRITER.lock().set(&*CONSOLE_SERIAL);
    init_console();

    // Console is fully working now and any unsupported configuration can be
    // properly reported.
    dump_cpuid_table();
    platform.env_setup_late();
}

fn map_and_validate(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    vregion: MemoryRegion<VirtAddr>,
    paddr: PhysAddr,
) {
    let flags = PTEntryFlags::PRESENT
        | PTEntryFlags::WRITABLE
        | PTEntryFlags::ACCESSED
        | PTEntryFlags::DIRTY;

    let mut pgtbl = get_init_pgtable_locked();
    pgtbl
        .map_region(vregion, paddr, flags)
        .expect("Error mapping kernel region");

    if config.page_state_change_required() {
        platform
            .page_state_change(paddr, paddr + vregion.len(), PageSize::Huge, true)
            .expect("GHCB::PAGE_STATE_CHANGE call failed for kernel region");
    }
    platform
        .pvalidate_range(vregion, true)
        .expect("PVALIDATE kernel region failed");
    valid_bitmap_set_valid_range(paddr, paddr + vregion.len());
}

#[inline]
fn check_launch_info(launch_info: &KernelLaunchInfo) {
    let offset: u64 = launch_info.heap_area_virt_start - launch_info.heap_area_phys_start;
    let align: u64 = PAGE_SIZE_2M.try_into().unwrap();

    assert!(is_aligned(offset, align));
}

#[no_mangle]
pub extern "C" fn stage2_main(launch_info: &Stage2LaunchInfo) {
    let kernel_elf_start: PhysAddr = PhysAddr::from(launch_info.kernel_elf_start as u64);
    let kernel_elf_end: PhysAddr = PhysAddr::from(launch_info.kernel_elf_end as u64);

    let platform_type = SvsmPlatformType::from_u32(launch_info.platform_type);
    let mut platform_cell = SvsmPlatformCell::new(platform_type);
    let platform = platform_cell.as_mut_dyn_ref();

    let config = if launch_info.igvm_params != 0 {
        let igvm_params = IgvmParams::new(VirtAddr::from(launch_info.igvm_params as u64))
            .expect("Invalid IGVM parameters");
        SvsmConfig::IgvmConfig(igvm_params)
    } else {
        SvsmConfig::FirmwareConfig(FwCfg::new(platform.get_console_io_port()))
    };

    setup_env(&config, platform, launch_info);

    let r = config
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    log::info!("COCONUT Secure Virtual Machine Service Module (SVSM) Stage 2 Loader");

    let kernel_region_phys_start = r.start();
    let kernel_region_phys_end = r.end();
    init_valid_bitmap_alloc(r).expect("Failed to allocate valid-bitmap");

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

    // Determine the starting physical address at which the kernel should be
    // relocated.
    let mut loaded_kernel_phys_end = kernel_region_phys_start;

    // Map, validate and populate the SVSM kernel ELF's PT_LOAD segments. The
    // segments' virtual address range might not necessarily be contiguous,
    // track their total extent along the way. Physical memory is successively
    // being taken from the physical memory region, the remaining space will be
    // available as heap space for the SVSM kernel. Remember the end of all
    // physical memory occupied by the loaded ELF image.
    let mut loaded_kernel_virt_start: Option<VirtAddr> = None;
    let mut loaded_kernel_virt_end = VirtAddr::null();
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
        loaded_kernel_phys_end = loaded_kernel_phys_end + segment_len;

        let vregion = MemoryRegion::new(vaddr_start, segment_len);
        map_and_validate(platform, &config, vregion, paddr_start);

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

    // If IGVM parameters are present, then map them into the address space
    // after the kernel.
    let mut igvm_params_virt_address = VirtAddr::null();
    let mut igvm_params_phys_address = PhysAddr::null();
    let mut igvm_params_size = 0;
    if let SvsmConfig::IgvmConfig(ref igvm_params) = config {
        igvm_params_virt_address = loaded_kernel_virt_end;
        igvm_params_phys_address = loaded_kernel_phys_end;
        igvm_params_size = igvm_params.size();

        let igvm_params_vregion = MemoryRegion::new(igvm_params_virt_address, igvm_params_size);
        map_and_validate(
            platform,
            &config,
            igvm_params_vregion,
            igvm_params_phys_address,
        );

        let igvm_params_src_addr = VirtAddr::from(launch_info.igvm_params as u64);
        let igvm_src =
            unsafe { slice::from_raw_parts(igvm_params_src_addr.as_ptr::<u8>(), igvm_params_size) };
        let igvm_dest = unsafe {
            slice::from_raw_parts_mut(
                igvm_params_virt_address.as_mut_ptr::<u8>(),
                igvm_params_size,
            )
        };
        igvm_dest.copy_from_slice(igvm_src);

        loaded_kernel_virt_end = loaded_kernel_virt_end + igvm_params_size;
        loaded_kernel_phys_end = loaded_kernel_phys_end + igvm_params_size;
    }

    // Map the rest of the memory region to right after the kernel image.
    // Exclude any memory reserved by the configuration.
    let heap_area_phys_start = loaded_kernel_phys_end;
    let heap_area_virt_start = loaded_kernel_virt_end;
    let heap_area_size =
        kernel_region_phys_end - heap_area_phys_start - config.reserved_kernel_area_size();
    log::info!("HEAP SIZE {} {} {}",kernel_region_phys_end,heap_area_phys_start, config.reserved_kernel_area_size());
    //panic!();
    let heap_area_virt_region = MemoryRegion::new(heap_area_virt_start, heap_area_size);
    map_and_validate(
        platform,
        &config,
        heap_area_virt_region,
        heap_area_phys_start,
    );

    // Build the handover information describing the memory layout and hand
    // control to the SVSM kernel.
    let launch_info = KernelLaunchInfo {
        kernel_region_phys_start: u64::from(kernel_region_phys_start),
        kernel_region_phys_end: u64::from(kernel_region_phys_end),
        heap_area_phys_start: u64::from(heap_area_phys_start),
        heap_area_size: heap_area_size as u64,
        kernel_region_virt_start: u64::from(loaded_kernel_virt_start),
        heap_area_virt_start: u64::from(heap_area_virt_start),
        kernel_elf_stage2_virt_start: u64::from(kernel_elf_start),
        kernel_elf_stage2_virt_end: u64::from(kernel_elf_end),
        kernel_fs_start: u64::from(launch_info.kernel_fs_start),
        kernel_fs_end: u64::from(launch_info.kernel_fs_end),
        cpuid_page: config.get_cpuid_page_address(),
        secrets_page: config.get_secrets_page_address(),
        stage2_igvm_params_phys_addr: u64::from(launch_info.igvm_params),
        stage2_igvm_params_size: igvm_params_size as u64,
        igvm_params_phys_addr: u64::from(igvm_params_phys_address),
        igvm_params_virt_addr: u64::from(igvm_params_virt_address),
        vtom: launch_info.vtom,
        debug_serial_port: config.debug_serial_port(),
        platform_type,
    };

    check_launch_info(&launch_info);

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
fn panic(info: &PanicInfo<'_>) -> ! {
    log::error!("Panic: {}", info);
    loop {
        halt();
    }
}
