// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

pub mod boot_stage2;

use bootlib::kernel_launch::{
    KernelLaunchInfo, Stage2LaunchInfo, LOWMEM_END, STAGE2_HEAP_END, STAGE2_HEAP_START,
    STAGE2_STACK, STAGE2_STACK_END, STAGE2_START,
};
use bootlib::platform::SvsmPlatformType;
use core::arch::asm;
use core::mem;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::slice;
use core::sync::atomic::{AtomicU32, Ordering};
use cpuarch::snp_cpuid::SnpCpuidTable;
use elf::ElfError;
use svsm::address::{Address, PhysAddr, VirtAddr};
use svsm::config::SvsmConfig;
use svsm::console::install_console_logger;
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::flush_tlb_percpu;
use svsm::cpu::gdt::GLOBAL_GDT;
use svsm::cpu::idt::stage2::{early_idt_init, early_idt_init_no_ghcb};
use svsm::cpu::idt::{IdtEntry, EARLY_IDT_ENTRIES, IDT};
use svsm::cpu::percpu::{this_cpu, PerCpu, PERCPU_AREAS};
use svsm::debug::stacktrace::print_stack;
use svsm::error::SvsmError;
use svsm::igvm_params::IgvmParams;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init, AllocError};
use svsm::mm::pagetable::{paging_init, PTEntryFlags, PageTable};
use svsm::mm::{
    init_kernel_mapping_info, FixedAddressMappingRange, STACK_GUARD_SIZE, STACK_SIZE,
    SVSM_PERCPU_BASE,
};
use svsm::platform;
use svsm::platform::{
    init_platform_type, PageStateChangeOp, PageValidateOp, Stage2PlatformCell, SvsmPlatform,
    SvsmPlatformCell,
};
use svsm::types::{PageSize, PAGE_SIZE};
use svsm::utils::{round_to_pages, zero_mem_region, MemoryRegion};

use release::COCONUT_VERSION;

extern "C" {
    static ap_flag: AtomicU32; // 4-byte aligned
    static mut pgtable: PageTable;
}

#[derive(Debug)]
pub struct KernelHeap {
    virt_base: VirtAddr,
    phys_base: PhysAddr,
    page_count: usize,
    next_free: usize,
}

impl KernelHeap {
    pub fn create(virt_base: VirtAddr, prange: MemoryRegion<PhysAddr>) -> Self {
        Self {
            virt_base,
            phys_base: prange.start(),
            page_count: prange.len() / PAGE_SIZE,
            next_free: 0,
        }
    }

    pub fn virt_base(&self) -> VirtAddr {
        self.virt_base
    }

    pub fn phys_base(&self) -> PhysAddr {
        self.phys_base
    }

    pub fn page_count(&self) -> usize {
        self.page_count
    }

    pub fn next_free(&self) -> usize {
        self.next_free
    }

    pub fn allocate(&mut self, size: usize) -> Result<(VirtAddr, PhysAddr), SvsmError> {
        let page_count = round_to_pages(size);
        self.allocate_pages(page_count)
    }

    pub fn allocate_pages(&mut self, page_count: usize) -> Result<(VirtAddr, PhysAddr), SvsmError> {
        // Verify that this allocation will not overflow the heap.
        let next_free = self.next_free + page_count;
        if next_free > self.page_count {
            return Err(AllocError::OutOfMemory.into());
        }

        // Calculate the allocation base based on the current position within
        // the heap.
        let offset = self.next_free * PAGE_SIZE;
        let virt_addr = self.virt_base + offset;
        let phys_addr = self.phys_base + offset;

        // Move the allocation cursor beyond this allocation.
        self.next_free = next_free;
        Ok((virt_addr, phys_addr))
    }
}

fn setup_stage2_allocator(heap_start: u64, heap_end: u64) {
    let vstart = VirtAddr::from(heap_start);
    let vend = VirtAddr::from(heap_end);
    let pstart = PhysAddr::from(vstart.bits()); // Identity mapping
    let nr_pages = (vend - vstart) / PAGE_SIZE;

    root_mem_init(pstart, vstart, nr_pages, 0);
}

fn init_percpu(platform: &mut dyn SvsmPlatform) -> Result<(), SvsmError> {
    // SAFETY: this is the first CPU, so there can be no other dependencies
    // on multi-threaded access to the per-cpu areas.
    let percpu_shared = unsafe { PERCPU_AREAS.create_new(0) };
    let bsp_percpu = PerCpu::alloc(percpu_shared)?;
    bsp_percpu.set_current_stack(MemoryRegion::from_addresses(
        VirtAddr::from(STAGE2_STACK_END as u64),
        VirtAddr::from(STAGE2_STACK as u64),
    ));
    // SAFETY: pgtable is properly aligned and is never freed within the
    // lifetime of stage2. We go through a raw pointer to promote it to a
    // static mut. Only the BSP is able to get a reference to it so no
    // aliasing can occur.
    let init_pgtable = unsafe { (&raw mut pgtable).as_mut().unwrap() };
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
    // SAFETY: ptr is properly aligned but the caller must ensure the PerCpu
    // structure is valid and not aliased.
    unsafe {
        core::ptr::drop_in_place(ptr);
    }
    // SAFETY: pgtable is properly aligned and is never freed within the
    // lifetime of stage2. We go through a raw pointer to promote it to a
    // static mut. Only the BSP is able to get a reference to it so no
    // aliasing can occur.
    let init_pgtable = unsafe { (&raw mut pgtable).as_mut().unwrap() };
    init_pgtable.unmap_4k(SVSM_PERCPU_BASE);
    flush_tlb_percpu();
}

// SAFETY: the caller must guarantee that the IDT specified here will remain
// in scope until a new IDT is loaded.
unsafe fn setup_env(
    config: &SvsmConfig<'_>,
    platform: &mut dyn SvsmPlatform,
    launch_info: &Stage2LaunchInfo,
    cpuid_vaddr: Option<VirtAddr>,
    idt: &mut IDT<'_>,
) {
    GLOBAL_GDT.load_selectors();
    // SAFETY: the caller guarantees that the lifetime of this IDT is suitable.
    unsafe {
        early_idt_init_no_ghcb(idt);
    }

    let debug_serial_port = config.debug_serial_port();
    install_console_logger("Stage2").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port, launch_info.vtom.try_into().unwrap())
        .expect("Early environment setup failed");

    let kernel_mapping = FixedAddressMappingRange::new(
        VirtAddr::from(u64::from(STAGE2_START)),
        VirtAddr::from(u64::from(launch_info.stage2_end)),
        PhysAddr::from(u64::from(STAGE2_START)),
    );

    if let Some(cpuid_addr) = cpuid_vaddr {
        // SAFETY: the CPUID page address specified in the launch info was
        // mapped by the loader, which promises to supply a correctly formed
        // CPUID page at that address.
        let cpuid_page = unsafe { &*cpuid_addr.as_ptr::<SnpCpuidTable>() };
        register_cpuid_table(cpuid_page);
    }

    paging_init(platform, true).expect("Failed to initialize early paging");

    // Use the low 640 KB of memory as the heap.
    let lowmem_region =
        MemoryRegion::from_addresses(VirtAddr::from(0u64), VirtAddr::from(u64::from(LOWMEM_END)));
    let heap_mapping = FixedAddressMappingRange::new(
        lowmem_region.start(),
        lowmem_region.end(),
        PhysAddr::from(0u64),
    );
    init_kernel_mapping_info(kernel_mapping, Some(heap_mapping));

    // Now that the heap virtual-to-physical mapping has been established,
    // validate the first 640 KB of memory so it can be used if necessary.
    // SAFETY: the low memory region is known not to overlap any memory in use.
    unsafe {
        platform
            .validate_virtual_page_range(lowmem_region, PageValidateOp::Validate)
            .expect("failed to validate low 640 KB");
    }

    // SAFETY: ap_flag is an extern static and this is the only place where we
    // get a reference to it.
    unsafe {
        // Allow APs to proceed as the environment is now ready.
        //
        // Although APs use non-atomic loads in the ap_wait_for_env spin loop,
        // the language and architectural guarantees of this atomic store (e.g.
        // the compiler cannot move the previous stores past this atomic
        // store-release, and x86 is a strongly-ordered system) make setting
        // this flag more deterministic.
        ap_flag.store(1, Ordering::Release);
    }

    // Configure the heap.
    setup_stage2_allocator(STAGE2_HEAP_START.into(), STAGE2_HEAP_END.into());

    init_percpu(platform).expect("Failed to initialize per-cpu area");

    // Init IDT again with handlers requiring GHCB (eg. #VC handler)
    // Must be done after init_percpu() to catch early #PFs
    //
    // SAFETY: the caller guarantees that the lifetime of this IDT is suitable.
    unsafe {
        early_idt_init(idt);
    }

    // Complete initializtion of the platform.  After that point, the console
    // will be fully working and any unsupported configuration can be properly
    // reported.
    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    if cpuid_vaddr.is_some() {
        dump_cpuid_table();
    }
}

/// # Safety
/// The caller is required to ensure that the source virtual address maps to
/// a valid page of data that can be copied.
unsafe fn copy_page_to_kernel(
    src_vaddr: VirtAddr,
    kernel_heap: &mut KernelHeap,
) -> Result<VirtAddr, SvsmError> {
    let (dst_vaddr, _) = kernel_heap.allocate(PAGE_SIZE)?;
    // SAFETY: the caller take responsibility for the correctness of the source
    // address, and the destination address is known to be correct because it
    // was just allocated as a full page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src_vaddr.as_ptr::<u8>(),
            dst_vaddr.as_mut_ptr::<u8>(),
            PAGE_SIZE,
        );
    }

    Ok(dst_vaddr)
}

/// Map and validate the specified virtual memory region at the given physical
/// address.
/// # Safety
/// The caller is required to ensure the safety of the virtual address range.
unsafe fn map_and_validate(
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
    // SAFETY: the caller has ensured the safety of the virtual address range.
    unsafe {
        platform.validate_virtual_page_range(vregion, PageValidateOp::Validate)?;
    }

    Ok(())
}

/// Loads a single ELF segment and returns its virtual memory region.
/// # Safety
/// The caller is required to supply an appropriate virtual address for this
/// ELF segment.
unsafe fn load_elf_segment(
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
    // SAFETY: the caller has verified the safety of this virtual address
    // region.
    unsafe {
        map_and_validate(platform, config, segment_region, paddr)?;
    }

    // Copy the segment contents and pad with zeroes
    // SAFETY: the caller guarantees the correctness of the ELF segment's
    // virtual address range.
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
    // SAFETY: the base address of the ELF image was selected by the loader and
    // is known not to conflict with any other virtual address mappings.
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
        // SAFETY: the virtual address is calculated based on the base address
        // of the image and the previously loaded segments, so it is correct
        // for use.
        let region = unsafe { load_elf_segment(segment, loaded_phys.end(), platform, config)? };
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
            // SAFETY: the relocation address is known to be correct. The ELF loader rejects
            // relocations that point outside a PT_LOAD segment.
            let dst = unsafe { slice::from_raw_parts_mut(reloc.dst as *mut u8, reloc.value_len) };
            let src = &reloc.value[..reloc.value_len];
            dst.copy_from_slice(src)
        }
    }

    let entry = VirtAddr::from(elf.get_entry(vaddr_alloc_base));
    let region = MemoryRegion::from_addresses(load_virt_start, load_virt_end);
    Ok((entry, region))
}

/// Loads the IGVM params.  Returns the virtual and physical memory regions
/// containing the loaded data.
/// # Safety
/// Ther caller is required to specify the correct virtual address for the
/// kernel virtual region.
fn load_igvm_params(
    kernel_heap: &mut KernelHeap,
    config: &SvsmConfig<'_>,
    launch_info: &Stage2LaunchInfo,
) -> Result<VirtAddr, SvsmError> {
    let params = config.get_igvm_params();
    let params_size = params.size();

    // Allocate space in the kernel area to hold the parameters.
    let (vaddr, _) = kernel_heap.allocate(params_size)?;

    // Copy the contents over
    let src_addr = VirtAddr::from(launch_info.igvm_params as u64);
    // SAFETY: the source address specified in the launch info was mapped
    // by the loader, which promises to supply a correctly formed IGRM
    // parameter block
    let igvm_src = unsafe { slice::from_raw_parts(src_addr.as_ptr::<u8>(), params_size) };
    // SAFETY: the destination address came from the heap allocation above and
    // can be used safely.
    let igvm_dst = unsafe { slice::from_raw_parts_mut(vaddr.as_mut_ptr::<u8>(), params_size) };
    igvm_dst.copy_from_slice(igvm_src);

    Ok(vaddr)
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
    heap_base_vaddr: VirtAddr,
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
) -> Result<KernelHeap, SvsmError> {
    // Heap starts after kernel
    let heap_pstart = loaded_kernel_pregion.end();

    // Compute size, excluding any memory reserved by the configuration.
    let heap_size = kernel_region
        .end()
        .checked_sub(heap_pstart.into())
        .and_then(|r| r.checked_sub(config.reserved_kernel_area_size()))
        .expect("Insufficient physical space for kernel image")
        .into();
    let heap_pregion = MemoryRegion::new(heap_pstart, heap_size);
    let heap_vregion = MemoryRegion::new(heap_base_vaddr, heap_size);

    // SAFETY: the virtual address range was computed so it is within the valid
    // region and does not collide with the kernel.
    unsafe {
        map_and_validate(platform, config, heap_vregion, heap_pregion.start())?;
    }

    Ok(KernelHeap::create(heap_base_vaddr, heap_pregion))
}

#[no_mangle]
pub extern "C" fn stage2_main(launch_info: &Stage2LaunchInfo) -> ! {
    let platform_type = SvsmPlatformType::from(launch_info.platform_type);

    init_platform_type(platform_type);
    let mut platform_cell = SvsmPlatformCell::new(true);
    let platform = platform_cell.platform_mut();
    let stage2_platform_cell = Stage2PlatformCell::new(platform_type);
    let stage2_platform = stage2_platform_cell.platform();

    // SAFETY: the address in the launch info is known to be correct.
    let igvm_params = unsafe { IgvmParams::new(VirtAddr::from(launch_info.igvm_params as u64)) }
        .expect("Failed to get IGVM parameters");
    let config = SvsmConfig::new(&igvm_params);

    // Set up space for an early IDT.  This will remain in scope as long as
    // stage2 is in memory.
    let mut early_idt = [IdtEntry::no_handler(); EARLY_IDT_ENTRIES];
    let mut idt = IDT::new(&mut early_idt);

    // Get a reference to the CPUID page if this platform requires it.
    let cpuid_page = stage2_platform.get_cpuid_page(launch_info);

    // SAFETY: the IDT here will remain in scope until the full IDT is
    // initialized later, and thus can safely be used as the early IDT.
    unsafe {
        setup_env(&config, platform, launch_info, cpuid_page, &mut idt);
    }

    // Get the available physical memory region for the kernel
    let kernel_region = config
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    log::info!("SVSM memory region: {kernel_region:#018x}");

    // The physical memory region we've loaded so far
    let mut loaded_kernel_pregion = MemoryRegion::new(kernel_region.start(), 0);

    // Load first the kernel ELF and update the loaded physical region
    let (kernel_entry, loaded_kernel_vregion) =
        load_kernel_elf(launch_info, &mut loaded_kernel_pregion, platform, &config)
            .expect("Failed to load kernel ELF");

    // Define the heap base address as the end of the kernel ELF plus a
    // guard area for a stack.
    let heap_base_vaddr = loaded_kernel_vregion.end() + STACK_GUARD_SIZE;

    // Create the page heap used in the kernel region.
    let mut kernel_heap = prepare_heap(
        kernel_region,
        loaded_kernel_pregion,
        heap_base_vaddr,
        platform,
        &config,
    )
    .expect("Could not create kernel heap");

    // Allocate pages for an initial stack to be used in the kernel
    // environment.
    let (initial_stack_base, _) = kernel_heap
        .allocate(STACK_SIZE)
        .expect("Failed to allocate initial kernel stack");
    let initial_stack = initial_stack_base + STACK_SIZE;

    // Load the IGVM params, if present. Update loaded region accordingly.
    // SAFETY: The loaded kernel region was correctly calculated above and
    // is sized appropriately to include a copy of the IGVM parameters.
    let igvm_vaddr = load_igvm_params(&mut kernel_heap, &config, launch_info)
        .expect("Failed to load IGVM params");

    // Copy the CPUID page into the kernel address space if required.
    // SAFETY: the CPUID address is assumed to have been correctly retrieved
    // from the launch info by the stage2 platform object.
    let kernel_cpuid_page = unsafe {
        cpuid_page.map(|cpuid_addr| {
            copy_page_to_kernel(cpuid_addr, &mut kernel_heap).expect("Failed to copy CPUID page")
        })
    };

    // Determine whether this platforms uses a secrets pgae.
    let secrets_page = stage2_platform.get_secrets_page(launch_info);

    // Copy the secrets page into the kernel address space if required.
    let kernel_secrets_page = if let Some(secrets_page_vaddr) = secrets_page {
        // SAFETY: the secrets page address is assumed to have been correctly
        // configured in the stage2 image if it is present at all.
        unsafe {
            let new_vaddr = copy_page_to_kernel(secrets_page_vaddr, &mut kernel_heap)
                .expect("Failed to copy secrets page");
            zero_mem_region(secrets_page_vaddr, secrets_page_vaddr + PAGE_SIZE);
            Some(new_vaddr)
        }
    } else {
        None
    };

    // Determine whether use of interrupts on the SVSM should be suppressed.
    // This is required when running SNP under KVM/QEMU.
    let suppress_svsm_interrupts = match platform_type {
        SvsmPlatformType::Snp => config.suppress_svsm_interrupts_on_snp(),
        _ => false,
    };

    // Allocate memory in the kernel heap to hold the kernel launch parameters.
    let (launch_info_vaddr, _) = kernel_heap
        .allocate(mem::size_of::<KernelLaunchInfo>())
        .expect("Failed to allocate memory for kernel launch block");

    // Build the handover information describing the memory layout and hand
    // control to the SVSM kernel.
    let kernel_launch_info = KernelLaunchInfo {
        kernel_region_phys_start: u64::from(kernel_region.start()),
        kernel_region_phys_end: u64::from(kernel_region.end()),
        heap_area_phys_start: u64::from(kernel_heap.phys_base()),
        heap_area_virt_start: u64::from(kernel_heap.virt_base()),
        heap_area_page_count: kernel_heap.page_count().try_into().unwrap(),
        heap_area_allocated: kernel_heap.next_free().try_into().unwrap(),
        kernel_region_virt_start: u64::from(loaded_kernel_vregion.start()),
        kernel_elf_stage2_virt_start: u64::from(launch_info.kernel_elf_start),
        kernel_elf_stage2_virt_end: u64::from(launch_info.kernel_elf_end),
        kernel_fs_start: u64::from(launch_info.kernel_fs_start),
        kernel_fs_end: u64::from(launch_info.kernel_fs_end),
        stage2_start: 0x800000u64,
        stage2_end: launch_info.stage2_end as u64,
        cpuid_page: u64::from(kernel_cpuid_page.unwrap_or(VirtAddr::null())),
        secrets_page: u64::from(kernel_secrets_page.unwrap_or(VirtAddr::null())),
        stage2_igvm_params_phys_addr: u64::from(launch_info.igvm_params),
        stage2_igvm_params_size: igvm_params.size() as u64,
        igvm_params_virt_addr: u64::from(igvm_vaddr),
        vtom: launch_info.vtom,
        debug_serial_port: config.debug_serial_port(),
        use_alternate_injection: config.use_alternate_injection(),
        suppress_svsm_interrupts,
        platform_type,
    };

    // SAFETY: the virtual address of the allocated block is known to be usable
    // and is known to be uninitialized data which can be filled with the
    // computed launch information.
    unsafe {
        let kernel_launch_block =
            &mut *launch_info_vaddr.as_mut_ptr::<MaybeUninit<KernelLaunchInfo>>();
        kernel_launch_block.write(kernel_launch_info);
    };

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    log::info!(
        "  kernel_region_phys_start = {:#018x}",
        kernel_region.start()
    );
    log::info!("  kernel_region_phys_end   = {:#018x}", kernel_region.end());
    log::info!(
        "  kernel_virtual_base      = {:#018x}",
        loaded_kernel_vregion.start()
    );

    log::info!("Starting SVSM kernel...");

    // SAFETY: the addreses used to invoke the kernel have been calculated
    // correctly for use in the assembly trampoline.
    unsafe {
        // Shut down the PerCpu instance
        shutdown_percpu();

        asm!("jmp *%rax",
             in("rax") u64::from(kernel_entry),
             in("rdi") u64::from(launch_info_vaddr),
             in("rsi") u64::from(initial_stack),
             in("rdx") u64::from(initial_stack_base),
             options(att_syntax))
    };

    unreachable!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    log::error!("Panic! COCONUT-SVSM Version: {}", COCONUT_VERSION);
    log::error!("Info: {}", info);

    print_stack(3);

    loop {
        platform::halt();
    }
}
