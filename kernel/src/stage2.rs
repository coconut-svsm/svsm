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
use core::ptr::addr_of_mut;
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use elf::ElfError;
use svsm::address::{Address, PhysAddr, VirtAddr};
use svsm::config::SvsmConfig;
use svsm::console::install_console_logger;
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::gdt;
use svsm::cpu::idt::stage2::{early_idt_init, early_idt_init_no_ghcb};
use svsm::cpu::percpu::{this_cpu, PerCpu};
use svsm::error::SvsmError;
use svsm::fw_cfg::FwCfg;
use svsm::igvm_params::IgvmParams;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::pagetable::{paging_init_early, PTEntryFlags, PageTable};
use svsm::mm::validate::{
    init_valid_bitmap_alloc, valid_bitmap_addr, valid_bitmap_set_valid_range,
};
use svsm::mm::{init_kernel_mapping_info, FixedAddressMappingRange, SVSM_PERCPU_BASE};
use svsm::platform;
use svsm::platform::{
    init_platform_type, PageStateChangeOp, PageValidateOp, SvsmPlatform, SvsmPlatformCell,
};
use svsm::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use svsm::utils::{is_aligned, MemoryRegion};

extern "C" {
    static mut pgtable: PageTable;
}

fn setup_stage2_allocator(heap_start: u64, heap_end: u64) {
    let vstart = VirtAddr::from(heap_start);
    let vend = VirtAddr::from(heap_end);
    let pstart = PhysAddr::from(vstart.bits()); // Identity mapping
    let nr_pages = (vend - vstart) / PAGE_SIZE;

    root_mem_init(pstart, vstart, nr_pages);
}

fn init_percpu(platform: &mut dyn SvsmPlatform) -> Result<(), SvsmError> {
    let bsp_percpu = PerCpu::alloc(0)?;
    let init_pgtable = unsafe {
        // SAFETY: pgtable is a static mut and this is the only place where we
        // get a reference to it.
        &mut *addr_of_mut!(pgtable)
    };
    bsp_percpu.set_pgtable(init_pgtable);
    bsp_percpu.map_self_stage2()?;
    platform.setup_guest_host_comm(bsp_percpu, true);
    Ok(())
}

/// Release all resources in the `PerCpu` instance associated with the current
/// CPU.
///
/// # Safety
///
/// The caller must ensure that the `PerCpu` is never used again.
unsafe fn shutdown_percpu() {
    let ptr = SVSM_PERCPU_BASE.as_mut_ptr::<PerCpu>();
    unsafe {
        core::ptr::drop_in_place(ptr);
    }
}

fn setup_env(
    config: &SvsmConfig<'_>,
    platform: &mut dyn SvsmPlatform,
    launch_info: &Stage2LaunchInfo,
) {
    gdt().load();
    early_idt_init_no_ghcb();

    let debug_serial_port = config.debug_serial_port();
    install_console_logger("Stage2").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port, launch_info.vtom.try_into().unwrap())
        .expect("Early environment setup failed");

    let kernel_mapping = FixedAddressMappingRange::new(
        VirtAddr::from(0x808000u64),
        VirtAddr::from(launch_info.stage2_end as u64),
        PhysAddr::from(0x808000u64),
    );

    // Use the low 640 KB of memory as the heap.
    let lowmem_region = MemoryRegion::new(VirtAddr::from(0u64), 640 * 1024);
    let heap_mapping = FixedAddressMappingRange::new(
        lowmem_region.start(),
        lowmem_region.end(),
        PhysAddr::from(0u64),
    );
    init_kernel_mapping_info(kernel_mapping, Some(heap_mapping));

    // Now that the heap virtual-to-physical mapping has been established,
    // validate the first 640 KB of memory so it can be used if necessary.
    platform
        .validate_virtual_page_range(lowmem_region, PageValidateOp::Validate)
        .expect("failed to validate low 640 KB");

    let cpuid_page = unsafe { &*(launch_info.cpuid_page as *const SnpCpuidTable) };

    register_cpuid_table(cpuid_page);
    paging_init_early(platform).expect("Failed to initialize early paging");

    // Configure the heap to exist from 64 KB to 640 KB.
    setup_stage2_allocator(0x10000, 0xA0000);

    init_percpu(platform).expect("Failed to initialize per-cpu area");

    // Init IDT again with handlers requiring GHCB (eg. #VC handler)
    early_idt_init();

    // Complete initializtion of the platform.  After that point, the console
    // will be fully working and any unsupported configuration can be properly
    // reported.
    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    dump_cpuid_table();
}

/// Map and validate the specified virtual memory region at the given physical
/// address.
fn map_and_validate(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    vregion: MemoryRegion<VirtAddr>,
    paddr: PhysAddr,
) -> Result<(), SvsmError> {
    let flags = PTEntryFlags::PRESENT
        | PTEntryFlags::WRITABLE
        | PTEntryFlags::ACCESSED
        | PTEntryFlags::DIRTY;

    let mut pgtbl = this_cpu().get_pgtable();
    pgtbl.map_region(vregion, paddr, flags)?;

    if config.page_state_change_required() {
        platform.page_state_change(
            MemoryRegion::new(paddr, vregion.len()),
            PageSize::Huge,
            PageStateChangeOp::Private,
        )?;
    }
    platform.validate_virtual_page_range(vregion, PageValidateOp::Validate)?;
    valid_bitmap_set_valid_range(paddr, paddr + vregion.len());
    Ok(())
}

#[inline]
fn check_launch_info(launch_info: &KernelLaunchInfo) {
    let offset: u64 = launch_info.heap_area_virt_start - launch_info.heap_area_phys_start;
    let align: u64 = PAGE_SIZE_2M.try_into().unwrap();

    assert!(is_aligned(offset, align));
}

fn get_svsm_config(
    launch_info: &Stage2LaunchInfo,
    platform: &dyn SvsmPlatform,
) -> Result<SvsmConfig<'static>, SvsmError> {
    if launch_info.igvm_params == 0 {
        return Ok(SvsmConfig::FirmwareConfig(FwCfg::new(
            platform.get_io_port(),
        )));
    }

    IgvmParams::new(VirtAddr::from(launch_info.igvm_params as u64)).map(SvsmConfig::IgvmConfig)
}

/// Loads a single ELF segment and returns its virtual memory region.
fn load_elf_segment(
    segment: elf::Elf64ImageLoadSegment<'_>,
    paddr: PhysAddr,
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
) -> Result<MemoryRegion<VirtAddr>, SvsmError> {
    // Find the segment's bounds
    let segment_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
    let segment_end = VirtAddr::from(segment.vaddr_range.vaddr_end).page_align_up();
    let segment_len = segment_end - segment_start;
    let segment_region = MemoryRegion::new(segment_start, segment_len);

    // All ELF segments should be aligned to the page size. If not, there's
    // the risk of pvalidating a page twice, bail out if so. Note that the
    // ELF reading code had already verified that the individual segments,
    // with bounds specified as in the ELF file, are non-overlapping.
    if !segment_start.is_page_aligned() {
        return Err(SvsmError::Elf(ElfError::UnalignedSegmentAddress));
    }

    // Map and validate the segment at the next contiguous physical address
    map_and_validate(platform, config, segment_region, paddr)?;

    // Copy the segment contents and pad with zeroes
    let segment_buf =
        unsafe { slice::from_raw_parts_mut(segment_start.as_mut_ptr::<u8>(), segment_len) };
    let contents_len = segment.file_contents.len();
    segment_buf[..contents_len].copy_from_slice(segment.file_contents);
    segment_buf[contents_len..].fill(0);

    Ok(segment_region)
}

/// Loads the kernel ELF and returns the virtual memory region where it
/// resides, as well as its entry point. Updates the used physical memory
/// region accordingly.
fn load_kernel_elf(
    launch_info: &Stage2LaunchInfo,
    loaded_phys: &mut MemoryRegion<PhysAddr>,
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
) -> Result<(VirtAddr, MemoryRegion<VirtAddr>), SvsmError> {
    // Find the bounds of the kernel ELF and load it into the ELF parser
    let elf_start = PhysAddr::from(launch_info.kernel_elf_start as u64);
    let elf_end = PhysAddr::from(launch_info.kernel_elf_end as u64);
    let elf_len = elf_end - elf_start;
    let bytes = unsafe { slice::from_raw_parts(elf_start.bits() as *const u8, elf_len) };
    let elf = elf::Elf64File::read(bytes)?;

    let vaddr_alloc_info = elf.image_load_vaddr_alloc_info();
    let vaddr_alloc_base = vaddr_alloc_info.range.vaddr_begin;

    // Map, validate and populate the SVSM kernel ELF's PT_LOAD segments. The
    // segments' virtual address range might not necessarily be contiguous,
    // track their total extent along the way. Physical memory is successively
    // being taken from the physical memory region, the remaining space will be
    // available as heap space for the SVSM kernel. Remember the end of all
    // physical memory occupied by the loaded ELF image.
    let mut load_virt_start = None;
    let mut load_virt_end = VirtAddr::null();
    for segment in elf.image_load_segment_iter(vaddr_alloc_base) {
        let region = load_elf_segment(segment, loaded_phys.end(), platform, config)?;
        // Remember the mapping range's lower and upper bounds to pass it on
        // the kernel later. Note that the segments are being iterated over
        // here in increasing load order.
        if load_virt_start.is_none() {
            load_virt_start = Some(region.start());
        }
        load_virt_end = region.end();

        // Update to the next contiguous physical address
        *loaded_phys = loaded_phys.expand(region.len());
    }

    let Some(load_virt_start) = load_virt_start else {
        log::error!("No loadable segment found in kernel ELF");
        return Err(SvsmError::Mem);
    };

    // Apply relocations, if any
    if let Some(dyn_relocs) =
        elf.apply_dyn_relas(elf::Elf64X86RelocProcessor::new(), vaddr_alloc_base)?
    {
        for reloc in dyn_relocs {
            let Some(reloc) = reloc? else {
                continue;
            };
            let dst = unsafe { slice::from_raw_parts_mut(reloc.dst as *mut u8, reloc.value_len) };
            let src = &reloc.value[..reloc.value_len];
            dst.copy_from_slice(src)
        }
    }

    let entry = VirtAddr::from(elf.get_entry(vaddr_alloc_base));
    let region = MemoryRegion::from_addresses(load_virt_start, load_virt_end);
    Ok((entry, region))
}

/// Loads the IGVM params at the next contiguous location from the loaded
/// kernel image. Returns the virtual and physical memory regions hosting the
/// loaded data.
fn load_igvm_params(
    launch_info: &Stage2LaunchInfo,
    params: &IgvmParams<'_>,
    loaded_kernel_vregion: &MemoryRegion<VirtAddr>,
    loaded_kernel_pregion: &MemoryRegion<PhysAddr>,
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
) -> Result<(MemoryRegion<VirtAddr>, MemoryRegion<PhysAddr>), SvsmError> {
    // Map and validate destination region
    let igvm_vregion = MemoryRegion::new(loaded_kernel_vregion.end(), params.size());
    let igvm_pregion = MemoryRegion::new(loaded_kernel_pregion.end(), params.size());
    map_and_validate(platform, config, igvm_vregion, igvm_pregion.start())?;

    // Copy the contents over
    let src_addr = VirtAddr::from(launch_info.igvm_params as u64);
    let igvm_src = unsafe { slice::from_raw_parts(src_addr.as_ptr::<u8>(), igvm_vregion.len()) };
    let igvm_dst = unsafe {
        slice::from_raw_parts_mut(igvm_vregion.start().as_mut_ptr::<u8>(), igvm_vregion.len())
    };
    igvm_dst.copy_from_slice(igvm_src);

    Ok((igvm_vregion, igvm_pregion))
}

/// Maps any remaining memory between the end of the kernel image and the end
/// of the allocated kernel memory region as heap space. Exclude any memory
/// reserved by the configuration.
///
/// # Panics
///
/// Panics if the allocated kernel region (`kernel_region`) is not sufficient
/// to host the loaded kernel region (`loaded_kernel_pregion`) plus memory
/// reserved for configuration.
fn prepare_heap(
    kernel_region: MemoryRegion<PhysAddr>,
    loaded_kernel_pregion: MemoryRegion<PhysAddr>,
    loaded_kernel_vregion: MemoryRegion<VirtAddr>,
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
) -> Result<(MemoryRegion<VirtAddr>, MemoryRegion<PhysAddr>), SvsmError> {
    // Heap starts after kernel
    let heap_pstart = loaded_kernel_pregion.end();
    let heap_vstart = loaded_kernel_vregion.end();

    // Compute size, excluding any memory reserved by the configuration.
    let heap_size = kernel_region
        .end()
        .checked_sub(heap_pstart.into())
        .and_then(|r| r.checked_sub(config.reserved_kernel_area_size()))
        .expect("Insufficient physical space for kernel image")
        .into();
    let heap_pregion = MemoryRegion::new(heap_pstart, heap_size);
    let heap_vregion = MemoryRegion::new(heap_vstart, heap_size);

    map_and_validate(platform, config, heap_vregion, heap_pregion.start())?;

    Ok((heap_vregion, heap_pregion))
}

#[no_mangle]
pub extern "C" fn stage2_main(launch_info: &Stage2LaunchInfo) {
    let platform_type = SvsmPlatformType::from(launch_info.platform_type);

    init_platform_type(platform_type);
    let mut platform = SvsmPlatformCell::new(platform_type);

    let config =
        get_svsm_config(launch_info, &*platform).expect("Failed to get SVSM configuration");
    setup_env(&config, &mut *platform, launch_info);

    // Get the available physical memory region for the kernel
    let kernel_region = config
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    init_valid_bitmap_alloc(kernel_region).expect("Failed to allocate valid-bitmap");

    // The physical memory region we've loaded so far
    let mut loaded_kernel_pregion = MemoryRegion::new(kernel_region.start(), 0);

    // Load first the kernel ELF and update the loaded physical region
    let (kernel_entry, mut loaded_kernel_vregion) =
        load_kernel_elf(launch_info, &mut loaded_kernel_pregion, &*platform, &config)
            .expect("Failed to load kernel ELF");

    // Load the IGVM params, if present. Update loaded region accordingly.
    let (igvm_vregion, igvm_pregion) = if let SvsmConfig::IgvmConfig(ref igvm_params) = config {
        let (igvm_vregion, igvm_pregion) = load_igvm_params(
            launch_info,
            igvm_params,
            &loaded_kernel_vregion,
            &loaded_kernel_pregion,
            &*platform,
            &config,
        )
        .expect("Failed to load IGVM params");

        // Update the loaded kernel region
        loaded_kernel_pregion = loaded_kernel_pregion.expand(igvm_vregion.len());
        loaded_kernel_vregion = loaded_kernel_vregion.expand(igvm_pregion.len());
        (igvm_vregion, igvm_pregion)
    } else {
        (
            MemoryRegion::new(VirtAddr::null(), 0),
            MemoryRegion::new(PhysAddr::null(), 0),
        )
    };

    // Use remaining space after kernel image as heap space.
    let (heap_vregion, heap_pregion) = prepare_heap(
        kernel_region,
        loaded_kernel_pregion,
        loaded_kernel_vregion,
        &*platform,
        &config,
    )
    .expect("Failed to map and validate heap");

    // Build the handover information describing the memory layout and hand
    // control to the SVSM kernel.
    let launch_info = KernelLaunchInfo {
        kernel_region_phys_start: u64::from(kernel_region.start()),
        kernel_region_phys_end: u64::from(kernel_region.end()),
        heap_area_phys_start: u64::from(heap_pregion.start()),
        heap_area_virt_start: u64::from(heap_vregion.start()),
        heap_area_size: heap_vregion.len() as u64,
        kernel_region_virt_start: u64::from(loaded_kernel_vregion.start()),
        kernel_elf_stage2_virt_start: u64::from(launch_info.kernel_elf_start),
        kernel_elf_stage2_virt_end: u64::from(launch_info.kernel_elf_end),
        kernel_fs_start: u64::from(launch_info.kernel_fs_start),
        kernel_fs_end: u64::from(launch_info.kernel_fs_end),
        stage2_start: 0x800000u64,
        stage2_end: launch_info.stage2_end as u64,
        cpuid_page: launch_info.cpuid_page as u64,
        secrets_page: launch_info.secrets_page as u64,
        stage2_igvm_params_phys_addr: u64::from(launch_info.igvm_params),
        stage2_igvm_params_size: igvm_pregion.len() as u64,
        igvm_params_phys_addr: u64::from(igvm_pregion.start()),
        igvm_params_virt_addr: u64::from(igvm_vregion.start()),
        vtom: launch_info.vtom,
        debug_serial_port: config.debug_serial_port(),
        use_alternate_injection: config.use_alternate_injection(),
        platform_type,
    };

    check_launch_info(&launch_info);

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    log::info!(
        "  kernel_region_phys_start = {:#018x}",
        kernel_region.start()
    );
    log::info!("  kernel_region_phys_end   = {:#018x}", kernel_region.end());
    log::info!(
        "  kernel_virtual_base   = {:#018x}",
        loaded_kernel_vregion.start()
    );

    let valid_bitmap = valid_bitmap_addr();

    log::info!("Starting SVSM kernel...");

    // Shut down the GHCB
    unsafe {
        shutdown_percpu();

        asm!("jmp *%rax",
             in("rax") u64::from(kernel_entry),
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
        platform::halt();
    }
}
