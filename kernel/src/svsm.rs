// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use svsm::fw_meta::{print_fw_meta, validate_fw_memory, SevFWMetaData};

use bootlib::kernel_launch::KernelLaunchInfo;
use core::arch::global_asm;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr;
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use svsm::address::{PhysAddr, VirtAddr};
use svsm::config::SvsmConfig;
use svsm::console::install_console_logger;
use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::efer::efer_init;
use svsm::cpu::gdt;
use svsm::cpu::idt::svsm::{early_idt_init, idt_init};
use svsm::cpu::percpu::current_ghcb;
use svsm::cpu::percpu::PerCpu;
use svsm::cpu::percpu::{this_cpu, this_cpu_shared};
use svsm::cpu::smp::start_secondary_cpus;
use svsm::debug::gdbstub::svsm_gdbstub::{debug_break, gdbstub_start};
use svsm::debug::stacktrace::print_stack;
use svsm::error::SvsmError;
use svsm::fs::{initialize_fs, populate_ram_fs};
use svsm::fw_cfg::FwCfg;
use svsm::greq::driver::guest_request_driver_init;
use svsm::igvm_params::IgvmParams;
use svsm::kernel_region::new_kernel_region;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::memory::{init_memory_map, write_guest_memory_map};
use svsm::mm::pagetable::paging_init;
use svsm::mm::virtualrange::virt_log_usage;
use svsm::mm::{init_kernel_mapping_info, PerCPUPageMappingGuard};
use svsm::platform::{SvsmPlatformCell, SVSM_PLATFORM};
use svsm::requests::{request_loop, request_processing_main, update_mappings};
use svsm::sev::utils::{rmp_adjust, RMPFlags};
use svsm::sev::{secrets_page, secrets_page_mut};
use svsm::svsm_paging::{init_page_table, invalidate_early_boot_memory};
use svsm::task::exec_user;
use svsm::task::{create_kernel_task, schedule_init};
use svsm::types::{PageSize, GUEST_VMPL, PAGE_SIZE};
use svsm::utils::{halt, immut_after_init::ImmutAfterInitCell, zero_mem_region};
#[cfg(all(feature = "mstpm", not(test)))]
use svsm::vtpm::vtpm_init;

use svsm::mm::validate::{init_valid_bitmap_ptr, migrate_valid_bitmap};

extern "C" {
    pub static bsp_stack_end: u8;
}

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %r8  Pointer to the KernelLaunchInfo structure
 * %r9  Pointer to the valid-bitmap from stage2
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code64

        .globl  startup_64
    startup_64:
        /* Setup stack */
        leaq bsp_stack_end(%rip), %rsp

        /* Jump to rust code */
        movq    %r8, %rdi
        movq    %r9, %rsi
        jmp svsm_start

        .bss

        .align 4096
    bsp_stack:
        .fill 4*4096, 1, 0
    bsp_stack_end:
        "#,
    options(att_syntax)
);

static CPUID_PAGE: ImmutAfterInitCell<SnpCpuidTable> = ImmutAfterInitCell::uninit();
static LAUNCH_INFO: ImmutAfterInitCell<KernelLaunchInfo> = ImmutAfterInitCell::uninit();

const _: () = assert!(size_of::<SnpCpuidTable>() <= PAGE_SIZE);

fn copy_cpuid_table_to_fw(fw_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let start = guard.virt_addr().as_mut_ptr::<u8>();

    // SAFETY: this is called from CPU 0, so the underlying physical address
    // is not being aliased. We are mapping a full page, which is 4k-aligned,
    // and is enough for SnpCpuidTable. We also assert above at compile time
    // that SnpCpuidTable fits within a page, so the write is safe.
    unsafe {
        // Zero target and copy data
        start.write_bytes(0, PAGE_SIZE);
        start
            .cast::<SnpCpuidTable>()
            .copy_from_nonoverlapping(&*CPUID_PAGE, 1);
    }

    Ok(())
}

fn copy_secrets_page_to_fw(fw_addr: PhysAddr, caa_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let start = guard.virt_addr();

    // Zero target
    zero_mem_region(start, start + PAGE_SIZE);

    // Copy secrets page
    let mut fw_secrets_page = secrets_page().copy_for_vmpl(GUEST_VMPL);

    let &li = &*LAUNCH_INFO;

    fw_secrets_page.set_svsm_data(
        li.kernel_region_phys_start,
        li.kernel_region_phys_end - li.kernel_region_phys_start,
        u64::from(caa_addr),
    );

    // SAFETY: start points to a new allocated and zeroed page.
    unsafe {
        fw_secrets_page.copy_to(start);
    }

    Ok(())
}

fn zero_caa_page(fw_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let vaddr = guard.virt_addr();

    zero_mem_region(vaddr, vaddr + PAGE_SIZE);

    Ok(())
}

fn copy_tables_to_fw(fw_meta: &SevFWMetaData) -> Result<(), SvsmError> {
    if let Some(addr) = fw_meta.cpuid_page {
        copy_cpuid_table_to_fw(addr)?;
    }

    let secrets_page = fw_meta.secrets_page.ok_or(SvsmError::MissingSecrets)?;
    let caa_page = fw_meta.caa_page.ok_or(SvsmError::MissingCAA)?;

    copy_secrets_page_to_fw(secrets_page, caa_page)?;

    zero_caa_page(caa_page)?;

    Ok(())
}

fn prepare_fw_launch(fw_meta: &SevFWMetaData) -> Result<(), SvsmError> {
    if let Some(caa) = fw_meta.caa_page {
        this_cpu_shared().update_guest_caa(caa);
    }

    this_cpu().alloc_guest_vmsa()?;
    update_mappings()?;

    Ok(())
}

fn launch_fw(config: &SvsmConfig<'_>) -> Result<(), SvsmError> {
    let cpu = this_cpu();
    let mut vmsa_ref = cpu.guest_vmsa_ref();
    let vmsa_pa = vmsa_ref.vmsa_phys().unwrap();
    let vmsa = vmsa_ref.vmsa();

    config.initialize_guest_vmsa(vmsa)?;

    log::info!("VMSA PA: {:#x}", vmsa_pa);

    let sev_features = vmsa.sev_features;

    log::info!("Launching Firmware");
    current_ghcb().register_guest_vmsa(vmsa_pa, 0, GUEST_VMPL as u64, sev_features)?;

    Ok(())
}

fn validate_fw(config: &SvsmConfig<'_>, launch_info: &KernelLaunchInfo) -> Result<(), SvsmError> {
    let kernel_region = new_kernel_region(launch_info);
    let flash_regions = config.get_fw_regions(&kernel_region);

    for (i, region) in flash_regions.into_iter().enumerate() {
        log::info!(
            "Flash region {} at {:#018x} size {:018x}",
            i,
            region.start(),
            region.len(),
        );

        for paddr in region.iter_pages(PageSize::Regular) {
            let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
            let vaddr = guard.virt_addr();
            if let Err(e) = rmp_adjust(
                vaddr,
                RMPFlags::GUEST_VMPL | RMPFlags::RWX,
                PageSize::Regular,
            ) {
                log::info!("rmpadjust failed for addr {:#018x}", vaddr);
                return Err(e);
            }
        }
    }

    Ok(())
}

pub fn memory_init(launch_info: &KernelLaunchInfo) {
    root_mem_init(
        PhysAddr::from(launch_info.heap_area_phys_start),
        VirtAddr::from(launch_info.heap_area_virt_start),
        launch_info.heap_area_size as usize / PAGE_SIZE,
    );
}

pub fn boot_stack_info() {
    // SAFETY: this is only unsafe because `bsp_stack_end` is an extern
    // static, but we're simply printing its address. We are not creating a
    // reference so this is safe.
    let vaddr = unsafe { VirtAddr::from(ptr::addr_of!(bsp_stack_end)) };
    log::info!("Boot stack starts        @ {:#018x}", vaddr);
}

fn mapping_info_init(launch_info: &KernelLaunchInfo) {
    init_kernel_mapping_info(
        VirtAddr::from(launch_info.heap_area_virt_start),
        VirtAddr::from(launch_info.heap_area_virt_end()),
        PhysAddr::from(launch_info.heap_area_phys_start),
    );
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

    CPUID_PAGE
        .init(table)
        .expect("Already initialized CPUID page");
    register_cpuid_table(&CPUID_PAGE);
}

#[no_mangle]
pub extern "C" fn svsm_start(li: &KernelLaunchInfo, vb_addr: usize) {
    let launch_info: KernelLaunchInfo = *li;
    let vb_ptr = VirtAddr::new(vb_addr).as_mut_ptr::<u64>();

    mapping_info_init(&launch_info);

    init_valid_bitmap_ptr(new_kernel_region(&launch_info), vb_ptr);

    gdt().load();
    early_idt_init();

    // Capture the debug serial port before the launch info disappears from
    // the address space.
    let debug_serial_port = li.debug_serial_port;

    LAUNCH_INFO
        .init(li)
        .expect("Already initialized launch info");

    let mut platform_cell = SvsmPlatformCell::new(li.platform_type);
    let platform = platform_cell.as_mut_dyn_ref();

    init_cpuid_table(VirtAddr::from(launch_info.cpuid_page));

    let secrets_page_virt = VirtAddr::from(launch_info.secrets_page);

    // SAFETY: the secrets page address directly comes from IGVM.
    // We trust stage 2 to give the value provided by IGVM.
    unsafe {
        secrets_page_mut().copy_from(secrets_page_virt);
    }

    zero_mem_region(secrets_page_virt, secrets_page_virt + PAGE_SIZE);

    cr0_init();
    cr4_init();
    efer_init();
    install_console_logger("SVSM").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port)
        .expect("Early environment setup failed");

    memory_init(&launch_info);
    migrate_valid_bitmap().expect("Failed to migrate valid-bitmap");

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

    paging_init(platform, li.vtom).expect("Failed to initialize paging");
    init_page_table(&launch_info, &kernel_elf).expect("Could not initialize the page table");

    // SAFETY: this PerCpu has just been allocated and no other CPUs have been
    // brought up, thus it cannot be aliased and we can get a mutable
    // reference to it. We trust PerCpu::alloc() to return a valid and
    // aligned pointer.
    let bsp_percpu = PerCpu::alloc(0).expect("Failed to allocate BSP per-cpu data");

    bsp_percpu
        .setup(platform)
        .expect("Failed to setup BSP per-cpu area");
    bsp_percpu
        .setup_on_cpu(platform)
        .expect("Failed to run percpu.setup_on_cpu()");
    bsp_percpu.load();

    // Idle task must be allocated after PerCPU data is mapped
    bsp_percpu
        .setup_idle_task(svsm_main)
        .expect("Failed to allocate idle task for BSP");

    idt_init();
    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    dump_cpuid_table();

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    boot_stack_info();

    let bp = this_cpu().get_top_of_stack();
    log::info!("BSP Runtime stack starts @ {:#018x}", bp);

    platform
        .configure_alternate_injection(launch_info.use_alternate_injection)
        .expect("Alternate injection required but not available");

    SVSM_PLATFORM
        .init(&platform_cell)
        .expect("Failed to initialize SVSM platform object");

    schedule_init();

    panic!("SVSM entry point terminated unexpectedly");
}

#[no_mangle]
pub extern "C" fn svsm_main() {
    let platform = SVSM_PLATFORM.as_dyn_ref();

    // If required, the GDB stub can be started earlier, just after the console
    // is initialised in svsm_start() above.
    gdbstub_start().expect("Could not start GDB stub");
    // Uncomment the line below if you want to wait for
    // a remote GDB connection
    //debug_break();

    this_cpu()
        .configure_hv_doorbell()
        .expect("Failed to configure #HV doorbell");

    let launch_info = &*LAUNCH_INFO;
    let config = if launch_info.igvm_params_virt_addr != 0 {
        let igvm_params = IgvmParams::new(VirtAddr::from(launch_info.igvm_params_virt_addr))
            .expect("Invalid IGVM parameters");
        if (launch_info.vtom != 0) && (launch_info.vtom != igvm_params.get_vtom()) {
            panic!("Launch VTOM does not match VTOM from IGVM parameters");
        }
        SvsmConfig::IgvmConfig(igvm_params)
    } else {
        SvsmConfig::FirmwareConfig(FwCfg::new(SVSM_PLATFORM.as_dyn_ref().get_io_port()))
    };

    init_memory_map(&config, &LAUNCH_INFO).expect("Failed to init guest memory map");

    initialize_fs();

    populate_ram_fs(LAUNCH_INFO.kernel_fs_start, LAUNCH_INFO.kernel_fs_end)
        .expect("Failed to unpack FS archive");

    invalidate_early_boot_memory(platform, &config, launch_info)
        .expect("Failed to invalidate early boot memory");

    let cpus = config.load_cpu_info().expect("Failed to load ACPI tables");
    let mut nr_cpus = 0;

    for cpu in cpus.iter() {
        if cpu.enabled {
            nr_cpus += 1;
        }
    }

    log::info!("{} CPU(s) present", nr_cpus);

    start_secondary_cpus(platform, &cpus, launch_info.vtom);

    let fw_metadata = config.get_fw_metadata();
    if let Some(ref fw_meta) = fw_metadata {
        print_fw_meta(fw_meta);
        write_guest_memory_map(&config).expect("Failed to write guest memory map");
        validate_fw_memory(&config, fw_meta, &LAUNCH_INFO).expect("Failed to validate memory");
        copy_tables_to_fw(fw_meta).expect("Failed to copy firmware tables");
        validate_fw(&config, &LAUNCH_INFO).expect("Failed to validate flash memory");
    }

    guest_request_driver_init();

    if let Some(ref fw_meta) = fw_metadata {
        prepare_fw_launch(fw_meta).expect("Failed to setup guest VMSA/CAA");
    }

    #[cfg(all(feature = "mstpm", not(test)))]
    vtpm_init().expect("vTPM failed to initialize");

    {
        // Virtio drivers experiments
        log::info!("Virtio test trace");
        use svsm::virtio::test_mmio;
        test_mmio();
    }

    virt_log_usage();

    if config.should_launch_fw() {
        if let Err(e) = launch_fw(&config) {
            panic!("Failed to launch FW: {:#?}", e);
        }
    }

    create_kernel_task(request_processing_main).expect("Failed to launch request processing task");

    #[cfg(test)]
    crate::test_main();

    if exec_user("/init").is_err() {
        log::info!("Failed to launch /init");
    }

    request_loop();

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    secrets_page_mut().clear_vmpck(0);
    secrets_page_mut().clear_vmpck(1);
    secrets_page_mut().clear_vmpck(2);
    secrets_page_mut().clear_vmpck(3);

    log::error!("Panic: CPU[{}] {}", this_cpu().get_apic_id(), info);

    print_stack(3);

    loop {
        debug_break();
        halt();
    }
}
