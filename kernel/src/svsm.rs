// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use bootlib::kernel_launch::KernelLaunchInfo;
use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use svsm::address::{Address, PhysAddr, VirtAddr};
#[cfg(feature = "attest")]
use svsm::attest::AttestationDriver;
use svsm::config::SvsmConfig;
use svsm::console::install_console_logger;
use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::gdt::GLOBAL_GDT;
use svsm::cpu::idt::svsm::{early_idt_init, idt_init};
use svsm::cpu::idt::{IdtEntry, EARLY_IDT_ENTRIES, IDT};
use svsm::cpu::percpu::{cpu_idle_loop, this_cpu, try_this_cpu, PerCpu, PERCPU_AREAS};
use svsm::cpu::shadow_stack::{
    determine_cet_support, is_cet_ss_supported, set_cet_ss_enabled, shadow_stack_info, SCetFlags,
    MODE_64BIT, S_CET,
};
use svsm::cpu::smp::start_secondary_cpus;
use svsm::cpu::sse::sse_init;
use svsm::debug::gdbstub::svsm_gdbstub::{debug_break, gdbstub_start};
use svsm::debug::stacktrace::print_stack;
use svsm::enable_shadow_stacks;
use svsm::fs::{initialize_fs, populate_ram_fs};
use svsm::hyperv::hyperv_setup;
use svsm::igvm_params::IgvmBox;
use svsm::kernel_region::new_kernel_region;
use svsm::mm::alloc::{free_multiple_pages, memory_info, print_memory_info, root_mem_init};
use svsm::mm::memory::init_memory_map;
use svsm::mm::pagetable::paging_init;
use svsm::mm::ro_after_init::make_ro_after_init;
use svsm::mm::validate::init_valid_bitmap;
use svsm::mm::virtualrange::virt_log_usage;
use svsm::mm::{init_kernel_mapping_info, FixedAddressMappingRange, PageBox};
use svsm::platform;
use svsm::platform::{init_capabilities, init_platform_type, SvsmPlatformCell, SVSM_PLATFORM};
use svsm::sev::secrets_page::initialize_secrets_page;
use svsm::sev::secrets_page_mut;
use svsm::svsm_paging::{
    enumerate_early_boot_regions, init_page_table, invalidate_early_boot_memory,
};
use svsm::task::{schedule_init, start_kernel_task, KernelThreadStartInfo};
use svsm::types::PAGE_SIZE;
use svsm::utils::{MemoryRegion, ScopedRef};
#[cfg(all(feature = "vtpm", not(test)))]
use svsm::vtpm::vtpm_init;

use alloc::string::String;
use release::COCONUT_VERSION;

#[cfg(feature = "attest")]
use kbs_types::Tee;

extern "C" {
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
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code64

        .globl startup_64
    startup_64:
        /*
         * Setup stack.
         *
         * The initial stack is always mapped across all page tables because it
         * uses the shared PML4E, making it accessible after switching to the
         * first task's page table.
         *
         * See switch_to() for details.
         */
        movq %rsi, %rsp
        leaq bsp_stack_end(%rip), %rsi
        movq %rsp, (%rsi)
        leaq bsp_stack(%rip), %rsi
        movq %rdx, (%rsi)

        /* Mark the next stack frame as the bottom frame */
        xor %rbp, %rbp

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

pub fn memory_init(launch_info: &KernelLaunchInfo) {
    root_mem_init(
        PhysAddr::from(launch_info.heap_area_phys_start),
        VirtAddr::from(launch_info.heap_area_virt_start),
        launch_info.heap_area_page_count as usize,
        launch_info.heap_area_allocated as usize,
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

/// # Panics
///
/// Panics if the provided address is not aligned to a [`SnpCpuidTable`].
fn init_cpuid_table(addr: VirtAddr) {
    // SAFETY: this is called from the main function for the SVSM and no other
    // CPUs have been brought up, so the pointer cannot be aliased.
    // `aligned_mut()` will check alignment for us.
    let table = unsafe {
        addr.aligned_mut::<SnpCpuidTable>()
            .expect("Misaligned SNP CPUID table address")
    };

    for func in table.func.iter_mut().take(table.count as usize) {
        if func.eax_in == 0x8000001f {
            func.eax_out |= 1 << 28;
        }
    }

    register_cpuid_table(table);
}

/// # Safety
/// The caller must pass a valid pointer from the kernel heap as the launch
/// info pointer.
unsafe fn svsm_start(li: *const KernelLaunchInfo) -> Option<VirtAddr> {
    // SAFETY: the caller guarantees the correctness of the launch info
    // pointer.
    let launch_info = unsafe { ScopedRef::<KernelLaunchInfo>::new(li).unwrap() };
    init_platform_type(launch_info.platform_type);

    mapping_info_init(launch_info.as_ref());

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

    if launch_info.cpuid_page != 0 {
        init_cpuid_table(VirtAddr::from(launch_info.cpuid_page));
    }

    if launch_info.secrets_page != 0 {
        let secrets_page_virt = VirtAddr::from(launch_info.secrets_page);

        // SAFETY: the secrets page address was allocated by stage 2 in the kernel
        // heap and the address is trusted if it is non-zero.
        unsafe {
            initialize_secrets_page(secrets_page_virt);
        }
    }

    cr0_init();
    determine_cet_support(platform);
    cr4_init(platform);

    install_console_logger("SVSM").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port, launch_info.vtom.try_into().unwrap())
        .expect("Early environment setup failed");

    memory_init(launch_info.as_ref());

    // Initialize the valid bitmap as all valid, since stage2 guarantees that
    // all memory in the kernel region is validated prior to kernel entry.
    init_valid_bitmap(new_kernel_region(launch_info.as_ref()), true)
        .expect("Failed to allocate valid-bitmap");

    let kernel_elf_len = (launch_info.kernel_elf_stage2_virt_end
        - launch_info.kernel_elf_stage2_virt_start) as usize;
    let kernel_elf_buf_ptr = launch_info.kernel_elf_stage2_virt_start as *const u8;
    // SAFETY: we trust stage 2 to pass on a correct pointer and length. This
    // cannot be aliased because we are on CPU 0 and other CPUs have not been
    // brought up. The resulting slice is &[u8], so there are no alignment
    // requirements.
    let kernel_elf_buf = unsafe { slice::from_raw_parts(kernel_elf_buf_ptr, kernel_elf_len) };
    let kernel_elf = match elf::Elf64File::read(kernel_elf_buf) {
        Ok(kernel_elf) => kernel_elf,
        Err(e) => panic!("error reading kernel ELF: {}", e),
    };

    paging_init(platform, false).expect("Failed to initialize paging");
    let init_pgtable = init_page_table(launch_info.as_ref(), &kernel_elf)
        .expect("Could not initialize the page table");
    // SAFETY: we are initializing the state, including stack and registers
    unsafe {
        init_pgtable.load();
    }

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
    unsafe {
        bsp_percpu
            .setup_bsp_idle_task(svsm_main, li as usize)
            .expect("Failed to allocate idle task for BSP");
    }

    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    if launch_info.cpuid_page != 0 {
        dump_cpuid_table();
    }

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
#[no_mangle]
unsafe extern "C" fn svsm_entry(li: *mut KernelLaunchInfo) -> ! {
    // SAFETY: the caller ensures that the launch info pointer is a valid
    // pointer.
    let ssp_token = unsafe { svsm_start(li) };

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

    let stack_pages = (stack_end - stack_base).div_ceil(PAGE_SIZE);
    free_multiple_pages(stack_base, stack_pages);
}

fn svsm_init(launch_info: &KernelLaunchInfo) {
    // If required, the GDB stub can be started earlier, just after the console
    // is initialised in svsm_start() above.
    gdbstub_start(&**SVSM_PLATFORM).expect("Could not start GDB stub");
    // Uncomment the line below if you want to wait for
    // a remote GDB connection
    //debug_break();

    // Free the BSP stack that was allocated for early initialization.
    free_init_bsp_stack();

    SVSM_PLATFORM
        .env_setup_svsm()
        .expect("SVSM platform environment setup failed");

    hyperv_setup().expect("failed to complete Hyper-V setup");

    // SAFETY: the address in the launch info is known to be correct.
    let igvm_params = unsafe { IgvmBox::new(VirtAddr::from(launch_info.igvm_params_virt_addr)) }
        .expect("Invalid IGVM parameters");
    if (launch_info.vtom != 0) && (launch_info.vtom != igvm_params.get_vtom()) {
        panic!("Launch VTOM does not match VTOM from IGVM parameters");
    }

    let config = SvsmConfig::new(&igvm_params);

    init_memory_map(&config, launch_info).expect("Failed to init guest memory map");

    populate_ram_fs(launch_info.kernel_fs_start, launch_info.kernel_fs_end)
        .expect("Failed to unpack FS archive");

    init_capabilities();

    let cpus = config.load_cpu_info().expect("Failed to load ACPI tables");

    start_secondary_cpus(&**SVSM_PLATFORM, &cpus);

    // Make ro_after_init section read-only
    make_ro_after_init().expect("Failed to make ro_after_init region read-only");

    let kernel_region = new_kernel_region(launch_info);
    let early_boot_regions = enumerate_early_boot_regions(&config, launch_info);

    invalidate_early_boot_memory(&**SVSM_PLATFORM, &config, &early_boot_regions)
        .expect("Failed to invalidate early boot memory");

    if let Err(e) = SVSM_PLATFORM.prepare_fw(&config, kernel_region) {
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

    if let Err(e) = SVSM_PLATFORM.launch_fw(&config) {
        panic!("Failed to launch FW: {e:?}");
    }

    #[cfg(test)]
    {
        if config.has_qemu_testdev() {
            crate::testutils::set_has_qemu_testdev();
        }
        if config.has_test_iorequests() {
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
    svsm_init(launch_info.as_ref());

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
            "Panic on CPU[{}]! COCONUT-SVSM Version: {}",
            cpu.get_cpu_index(),
            COCONUT_VERSION
        );
    } else {
        log::error!("Panic on CPU[?]! COCONUT-SVSM Version: {}", COCONUT_VERSION);
    }
    log::error!("Info: {}", info);

    print_stack(3);

    loop {
        debug_break();
        #[cfg(all(test, test_in_svsm))]
        crate::testing::qemu_write_exit(crate::testing::QEMUExitValue::Fail);
        platform::halt();
    }
}
