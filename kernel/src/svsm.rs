// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use bootdefs::kernel_launch::KernelLaunchInfo;
use bootdefs::kernel_launch::LOWMEM_END;
use bootdefs::platform::SvsmPlatformType;
use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use svsm::address::{Address, PhysAddr, VirtAddr};
#[cfg(feature = "attest")]
use svsm::attest::AttestationDriver;
use svsm::boot_params::BootParamBox;
#[cfg(feature = "virtio-drivers")]
use svsm::boot_params::BootParams;
use svsm::console::install_console_logger;
use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::cpuid::dump_cpuid_table;
use svsm::cpu::gdt::GLOBAL_GDT;
use svsm::cpu::idt::svsm::{early_idt_init, idt_init};
use svsm::cpu::idt::{EARLY_IDT_ENTRIES, IDT, IdtEntry};
use svsm::cpu::percpu::{PERCPU_AREAS, PerCpu, cpu_idle_loop, this_cpu, try_this_cpu};
use svsm::cpu::shadow_stack::{
    MODE_64BIT, S_CET, SCetFlags, determine_cet_support, is_cet_ss_supported, set_cet_ss_enabled,
    shadow_stack_info,
};
use svsm::cpu::smp::start_secondary_cpus;
use svsm::cpu::sse::sse_init;
use svsm::debug::gdbstub::svsm_gdbstub::{debug_break, gdbstub_start};
use svsm::debug::stacktrace::print_stack;
use svsm::debug::symbols::init_symbols;
use svsm::enable_shadow_stacks;
#[cfg(feature = "virtio-drivers")]
use svsm::error::SvsmError;
use svsm::fs::{initialize_fs, populate_ram_fs};
use svsm::hyperv::hyperv_setup;
use svsm::kernel_region::new_kernel_region;
use svsm::mm::FixedAddressMappingRange;
use svsm::mm::PageBox;
use svsm::mm::TransitionPageTable;
use svsm::mm::alloc::{free_multiple_pages, memory_info, print_memory_info, root_mem_init};
use svsm::mm::global_memory::init_global_ranges;
use svsm::mm::init_kernel_mapping_info;
use svsm::mm::memory::init_memory_map;
use svsm::mm::pagetable::PageTable;
use svsm::mm::pagetable::paging_init;
use svsm::mm::ro_after_init::make_ro_after_init;
use svsm::mm::validate::init_valid_bitmap;
use svsm::mm::virtualrange::virt_log_usage;
use svsm::platform::PageValidateOp;
use svsm::platform::PlatformPageType;
use svsm::platform::SVSM_PLATFORM;
use svsm::platform::SvsmPlatform;
use svsm::platform::SvsmPlatformCell;
use svsm::platform::init_capabilities;
use svsm::platform::init_platform_type;
use svsm::sev::secrets_page_mut;
use svsm::svsm_paging::enumerate_early_boot_regions;
use svsm::svsm_paging::invalidate_early_boot_memory;
use svsm::task::{KernelThreadStartInfo, schedule_init, start_kernel_task};
use svsm::types::PAGE_SIZE;
use svsm::utils::{MemoryRegion, ScopedRef, round_to_pages};
#[cfg(all(feature = "virtio-drivers", feature = "block"))]
use svsm::virtio::probe_mmio_slots;
#[cfg(all(feature = "vtpm", not(test)))]
use svsm::vtpm::vtpm_init;

use alloc::string::String;
use release::COCONUT_VERSION;

#[cfg(feature = "attest")]
use kbs_types::Tee;

unsafe extern "C" {
    static bsp_stack: u64;
    static bsp_stack_end: u64;
}

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %rdi  Pointer to the KernelLaunchInfo structure
 * %rsi  Kernel stack pointer
 * %rdx  Kernel stack limit
 * %rcx  Kernel page tables
 */
global_asm!(
    r#"
        .section .text
        .section ".startup.text","ax"
        .code64

        .globl startup_64
    startup_64:
        /* Upon entry, the stack pointer is correctly set but the initial page
         * tables are not guaranteed to be set correctly.  Switch to the
         * correct page tables */
        popq %r15
        movq %r15, %cr3

        /* Mark the next stack frame as the bottom frame */
        xor %rbp, %rbp

        /* Capture the start parameter registers from the stack.  The platform
         * type is in rax and not the stack. */
        popq %rdi
        movq %rax, %rsi

        /* Capture the stack bounds into global variables.  The stack limit
         * (the low address) is the last value popped off the stack, and once
         * it has been popped, the stack pointer will represent the stack base
         * (the high address) */
        leaq bsp_stack(%rip), %r15
        popq %r14
        movq %r14, (%r15)
        leaq bsp_stack_end(%rip), %r15
        movq %rsp, (%r15)

        /*
         * Make sure (%rsp + 8) is 16b-aligned when control is transferred
         * to svsm_entry as required by the C calling convention for x86-64.
         */
        call svsm_entry
        int3

        .bss

        .align {PAGE_SIZE}
        .globl bsp_stack
    bsp_stack:
        .quad 0
        .globl bsp_stack_end
    bsp_stack_end:
        .quad 0
        "#,
    PAGE_SIZE = const PAGE_SIZE,
    options(att_syntax)
);

/// # Safety
/// The launch info block must correctly specify the initial state of the
/// heap.
unsafe fn memory_init(
    launch_info: &KernelLaunchInfo,
    platform: &dyn SvsmPlatform,
    platform_type: SvsmPlatformType,
) {
    // Unallocated heap memory has not already been accepted so it must be
    // accepted here.
    let heap_vaddr = VirtAddr::from(launch_info.heap_area_virt_start);
    let heap_allocated = launch_info.heap_area_allocated as usize;
    let mut heap_length = launch_info.heap_area_page_count as usize;

    // On an SNP system, the VMSA might be located within the kernel heap area.
    // If so, it is at the last page within the heap range, so the heap range
    // must be reduced so there is no attempt to validate the VMSA page and so
    // that the VMSA page is not reallocated
    if launch_info.vmsa_in_kernel_heap && (platform_type == SvsmPlatformType::Snp) {
        heap_length -= 1;
        assert!(heap_length >= heap_allocated);
    }

    if heap_allocated < heap_length {
        // SAFETY: the launch info is assumed to correctly reflect the set of
        // pages that were accepted as part of the boot image.
        unsafe {
            platform
                .validate_virtual_page_range(
                    MemoryRegion::new(
                        heap_vaddr + heap_allocated * PAGE_SIZE,
                        (heap_length - heap_allocated) * PAGE_SIZE,
                    ),
                    PageValidateOp::Validate,
                )
                .expect("Failed to validate heap memory");
        }
    }
    root_mem_init(
        PhysAddr::from(launch_info.heap_area_phys_start),
        heap_vaddr,
        heap_length,
        heap_allocated,
    );
}

fn boot_stack_info() {
    let bs = this_cpu().get_current_stack();
    log::info!("Boot stack @ {bs:#018x}");
}

fn mapping_info_init(launch_info: &KernelLaunchInfo) {
    let heap_start = VirtAddr::from(launch_info.heap_area_virt_start);
    let heap_size = launch_info.heap_area_page_count as usize * PAGE_SIZE;
    let kernel_mapping = FixedAddressMappingRange::new(
        heap_start,
        heap_start + heap_size,
        PhysAddr::from(launch_info.heap_area_phys_start),
    );
    init_kernel_mapping_info(kernel_mapping, None);
}

/// Probes for VirtIO MMIO devices and initializes them.
///
/// # Returns
///
/// Returns Ok if initialization is successful or no virtio devices are found
/// Returns an error when a virtio device is found but its driver initialization fails.
#[cfg(feature = "virtio-drivers")]
fn initialize_virtio_mmio(_boot_params: &BootParams<'_>) -> Result<(), SvsmError> {
    #[cfg(feature = "block")]
    {
        use svsm::block::virtio_blk::initialize_block;

        let mut slots = probe_mmio_slots(_boot_params);
        initialize_block(&mut slots)?;
    }

    Ok(())
}

/// # Safety
/// The caller must pass a valid pointer from the kernel heap as the launch
/// info pointer.
unsafe fn svsm_start(
    li: *const KernelLaunchInfo,
    platform_type: SvsmPlatformType,
) -> Option<VirtAddr> {
    // SAFETY: the caller guarantees the correctness of the launch info
    // pointer.
    let launch_info = unsafe { ScopedRef::<KernelLaunchInfo>::new(li).unwrap() };
    init_platform_type(platform_type);

    mapping_info_init(&launch_info);

    GLOBAL_GDT.load_selectors();

    let mut early_idt = [IdtEntry::default(); EARLY_IDT_ENTRIES];
    let mut idt = IDT::new(&mut early_idt);
    // SAFETY: the IDT here will remain in scope until the full IDT is
    // initialized later, and thus can safely be used as the early IDT.
    unsafe {
        early_idt_init(&mut idt);
    }

    // Capture the debug serial port before the launch info disappears from
    // the address space.
    let debug_serial_port = launch_info.debug_serial_port;

    let mut platform_cell = SvsmPlatformCell::new(launch_info.suppress_svsm_interrupts);
    let platform = platform_cell.platform_mut();

    // SAFETY: the CPUID and secrets page addresses were allocated in the
    // kernel heap and the addresses in the loader block are trusted.
    unsafe {
        platform.initialize_platform_page(
            PlatformPageType::Cpuid,
            VirtAddr::from(launch_info.cpuid_page),
        );
        platform.initialize_platform_page(
            PlatformPageType::Secrets,
            VirtAddr::from(launch_info.secrets_page),
        );
    }

    cr0_init();
    determine_cet_support(platform);
    cr4_init(platform);

    install_console_logger("SVSM").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port, launch_info.vtom.try_into().unwrap())
        .expect("Early environment setup failed");

    // Load symbol info now that there is a console
    init_symbols(&launch_info).expect("Could not initialize kernel symbols");

    paging_init(platform, false).expect("Failed to initialize paging");

    // SAFETY: THe launch info is assumed to correctly specify the initial
    // state of memory.
    unsafe {
        memory_init(launch_info.as_ref(), platform, platform_type);
    }

    // Initialize the valid bitmap as all valid, since stage2 guarantees that
    // all memory in the kernel region is validated prior to kernel entry.
    init_valid_bitmap(new_kernel_region(&launch_info), true)
        .expect("Failed to allocate valid-bitmap");

    // SAFETY: the current page table was allocated by stage2 from the kernel
    // heap and therefore it can be built into a PageBox.
    let init_pgtable: PageBox<PageTable> = unsafe {
        let page_table_ptr = (launch_info.kernel_page_table_vaddr as usize) as *mut PageTable;
        PageBox::from_raw(NonNull::new(page_table_ptr).unwrap())
    };

    init_global_ranges();

    // SAFETY: this is the first CPU, so there can be no other dependencies
    // on multi-threaded access to the per-cpu areas.
    let percpu_shared = unsafe { PERCPU_AREAS.create_new(0) };
    let bsp_percpu = PerCpu::alloc(percpu_shared).expect("Failed to allocate BSP per-cpu data");

    bsp_percpu
        .setup(platform, init_pgtable)
        .expect("Failed to setup BSP per-cpu area");
    bsp_percpu
        .setup_on_cpu(platform)
        .expect("Failed to run percpu.setup_on_cpu()");
    bsp_percpu.load();
    // Now the stack unwinder can be used
    // SAFETY: the stack addresses were initialized during kernel entry and
    // are known to be correct at this point.
    unsafe {
        bsp_percpu.set_current_stack(MemoryRegion::from_addresses(
            VirtAddr::from(bsp_stack),
            VirtAddr::from(bsp_stack_end),
        ));
    }

    idt_init().expect("Failed to allocate IDT");

    initialize_fs();

    // Idle task must be allocated after PerCPU data is mapped
    // SAFETY: the pointer to the launch information is the correct start
    // parameter for the startup routine.
    let start_info = unsafe { KernelThreadStartInfo::new_unsafe(svsm_main, li as usize) };
    bsp_percpu
        .setup_bsp_idle_task(start_info)
        .expect("Failed to allocate idle task for BSP");

    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    dump_cpuid_table();

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    boot_stack_info();

    platform
        .configure_alternate_injection(launch_info.use_alternate_injection)
        .expect("Alternate injection required but not available");

    platform_cell.global_init();

    sse_init();

    bsp_percpu.get_top_of_shadow_stack()
}

/// # Safety
/// Thus function must only be called from the entry from stage 2, where
/// the launch info parameter is known to have been allocated from the kernel
/// heap.
#[unsafe(no_mangle)]
unsafe extern "C" fn svsm_entry(li: *mut KernelLaunchInfo, platform_type: SvsmPlatformType) -> ! {
    // SAFETY: the caller ensures that the launch info pointer is a valid
    // pointer.
    let ssp_token = unsafe { svsm_start(li, platform_type) };

    // Shadow stacks must be enabled once no further function returns are
    // possible.
    if is_cet_ss_supported() {
        set_cet_ss_enabled();
        let ssp_token_addr = ssp_token.unwrap();
        enable_shadow_stacks!(ssp_token_addr);
    }
    shadow_stack_info();

    // SAFETY: there is no current task running on this processor yet, so
    // initializing the scheduler is safe.
    unsafe {
        schedule_init();
    }

    unreachable!("SVSM entry point terminated unexpectedly");
}

fn free_init_bsp_stack() {
    // SAFETY: the stack base and limit addresses were initialized when the
    // kernel was first started.
    let (stack_base, stack_end) =
        unsafe { (VirtAddr::from(bsp_stack), VirtAddr::from(bsp_stack_end)) };

    let stack_pages = round_to_pages(stack_end - stack_base);
    free_multiple_pages(stack_base, stack_pages);
}

fn svsm_init(launch_info: &KernelLaunchInfo) {
    // If required, the GDB stub can be started earlier, just after the console
    // is initialised in svsm_start() above.
    gdbstub_start(&**SVSM_PLATFORM).expect("Could not start GDB stub");
    // Uncomment the line below if you want to wait for
    // a remote GDB connection
    //debug_break();

    // Validate low memory if it was not validated in stage2.
    if !launch_info.lowmem_validated {
        // SAFETY: the launch information is trusted to represent the
        // validation state of memory, thus memory can safely be validated if
        // the launch info declares that it is necessary.
        unsafe {
            SVSM_PLATFORM
                .validate_low_memory(LOWMEM_END.into(), false)
                .expect("failed to validate low 640 KB");
        }
    }

    // Free the BSP stack that was allocated for early initialization.
    free_init_bsp_stack();

    // Free platform pages that were allocated but are not needed by the
    // current platform.
    // SAFETY: the virtual addresses of these pages are guaranteed to be
    // correct in the loader block, and the platform guarantees that freeing
    // the page is safe if the underlying page is not needed.
    unsafe {
        SVSM_PLATFORM.free_unused_platform_page(
            PlatformPageType::Cpuid,
            VirtAddr::from(launch_info.cpuid_page),
        );
        SVSM_PLATFORM.free_unused_platform_page(
            PlatformPageType::Secrets,
            VirtAddr::from(launch_info.secrets_page),
        );
    }

    SVSM_PLATFORM
        .env_setup_svsm()
        .expect("SVSM platform environment setup failed");

    hyperv_setup().expect("failed to complete Hyper-V setup");

    let boot_params =
        // SAFETY: the address in the launch info is known to be correct.
        unsafe { BootParamBox::new(VirtAddr::from(launch_info.boot_params_virt_addr)) }
            .expect("Invalid boot parameters");

    init_memory_map(&boot_params, launch_info).expect("Failed to init guest memory map");

    populate_ram_fs(launch_info.kernel_fs_start, launch_info.kernel_fs_end)
        .expect("Failed to unpack FS archive");

    init_capabilities();

    let cpus = boot_params
        .load_cpu_info()
        .expect("Failed to load ACPI tables");

    // Create a transition page table for use during CPU startup.
    let transition_page_table =
        // SAFETY: the address of the initial kernel page tables supplied in
        // the launch info is trusted to be correct.
        unsafe { TransitionPageTable::new() }.expect("Failed to create transition page table");

    start_secondary_cpus(&**SVSM_PLATFORM, &cpus, &transition_page_table);

    // Make ro_after_init section read-only
    make_ro_after_init().expect("Failed to make ro_after_init region read-only");

    let kernel_region = new_kernel_region(launch_info);
    let early_boot_regions = enumerate_early_boot_regions(&boot_params, launch_info);

    invalidate_early_boot_memory(&**SVSM_PLATFORM, &boot_params, &early_boot_regions)
        .expect("Failed to invalidate early boot memory");

    if let Err(e) = SVSM_PLATFORM.prepare_fw(&boot_params, kernel_region) {
        panic!("Failed to prepare guest FW: {e:#?}");
    }

    #[cfg(feature = "attest")]
    {
        let mut proxy = AttestationDriver::try_from(Tee::Snp).unwrap();
        let _data = proxy.attest().unwrap();

        // Nothing to do with data at the moment, simply print a success message.
        log::info!("attestation successful");
    }

    #[cfg(all(feature = "vtpm", not(test)))]
    vtpm_init().expect("vTPM failed to initialize");

    virt_log_usage();

    #[cfg(feature = "virtio-drivers")]
    initialize_virtio_mmio(&boot_params).expect("Failed to initialize virtio-mmio drivers");

    if let Err(e) = SVSM_PLATFORM.launch_fw(&boot_params, launch_info.vtom) {
        panic!("Failed to launch FW: {e:?}");
    }

    #[cfg(test)]
    {
        if boot_params.has_qemu_testdev() {
            crate::testutils::set_has_qemu_testdev();
        }
        if boot_params.has_test_iorequests() {
            crate::testutils::set_has_test_iorequests();
        }
        let _ = start_kernel_task(
            KernelThreadStartInfo::new(test_in_svsm_task, 0),
            String::from("SVSM test task"),
        );
    }

    #[cfg(not(test))]
    {
        use svsm::fs::opendir;
        use svsm::requests::request_loop_start;
        use svsm::task::exec_user;

        match exec_user("/init", opendir("/").expect("Failed to find FS root")) {
            Ok(_) => (),
            Err(e) => log::info!("Failed to launch /init: {e:?}"),
        }

        // Start request processing on this CPU if required.
        if SVSM_PLATFORM.start_svsm_request_loop() {
            start_kernel_task(
                KernelThreadStartInfo::new(request_loop_start, 0),
                String::from("request-loop on CPU 0"),
            )
            .expect("Failed to launch request loop task");
        }
    }
}

/// # Safety
/// The caller is required to ensure that the start parameter is a pointer to
/// a valid `KernelLaunchInfo` structure that was allocated from the kernel
/// heap..
pub unsafe fn svsm_main(li: usize) {
    // SAFETY: the caller takes responsibility for the correctness of the
    // pointer.
    let launch_info = unsafe {
        PageBox::<KernelLaunchInfo>::from_raw(NonNull::new(li as *mut KernelLaunchInfo).unwrap())
    };
    svsm_init(&launch_info);

    // The launch info is no lnoger used and can be freed now.
    drop(launch_info);

    cpu_idle_loop(0);
}

#[cfg(test)]
fn test_in_svsm_task(_context: usize) {
    crate::test_main();
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    if let Some(mut secrets_page) = secrets_page_mut() {
        secrets_page.clear_vmpck(0);
        secrets_page.clear_vmpck(1);
        secrets_page.clear_vmpck(2);
        secrets_page.clear_vmpck(3);
    }

    if let Some(cpu) = try_this_cpu() {
        log::error!(
            "Panic on CPU[{}]! COCONUT-SVSM Version: {COCONUT_VERSION}",
            cpu.get_cpu_index(),
        );
    } else {
        log::error!("Panic on CPU[?]! COCONUT-SVSM Version: {COCONUT_VERSION}");
    }
    log::error!("Info: {info}");

    print_stack(3);

    debug_break();

    // If we are running tests, notify qemu. Otherwise, simply
    // terminate the guest.
    #[cfg(all(test, test_in_svsm))]
    crate::testing::exit(crate::testing::QEMUExitValue::Fail);
    #[cfg(any(not(test), not(test_in_svsm)))]
    svsm::platform::terminate();
}
