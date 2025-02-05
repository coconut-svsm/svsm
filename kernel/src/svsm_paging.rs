// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::config::SvsmConfig;
use crate::error::SvsmError;
use crate::igvm_params::IgvmParams;
use crate::mm::global_memory::init_global_ranges;
use crate::mm::pagetable::{PTEntryFlags, PageTable};
use crate::mm::PageBox;
use crate::platform::{PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::types::PageSize;
use crate::utils::{page_align_up, MemoryRegion};
use bootlib::kernel_launch::{KernelLaunchInfo, LOWMEM_END};

struct IgvmParamInfo<'a> {
    virt_addr: VirtAddr,
    igvm_params: Option<IgvmParams<'a>>,
}

pub fn init_page_table(
    launch_info: &KernelLaunchInfo,
    kernel_elf: &elf::Elf64File<'_>,
) -> Result<PageBox<PageTable>, SvsmError> {
    let mut pgtable = PageTable::allocate_new()?;

    let igvm_param_info = if launch_info.igvm_params_virt_addr != 0 {
        let addr = VirtAddr::from(launch_info.igvm_params_virt_addr);
        IgvmParamInfo {
            virt_addr: addr,
            igvm_params: Some(IgvmParams::new(addr)?),
        }
    } else {
        IgvmParamInfo {
            virt_addr: VirtAddr::null(),
            igvm_params: None,
        }
    };

    // Install mappings for the kernel's ELF segments each.
    // The memory backing the kernel ELF segments gets allocated back to back
    // from the physical memory region by the Stage2 loader.
    let mut phys = PhysAddr::from(launch_info.kernel_region_phys_start);
    for segment in kernel_elf.image_load_segment_iter(launch_info.kernel_region_virt_start) {
        let vaddr_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
        let vaddr_end = VirtAddr::from(segment.vaddr_range.vaddr_end);
        let aligned_vaddr_end = vaddr_end.page_align_up();
        let segment_len = aligned_vaddr_end - vaddr_start;
        let flags = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
            PTEntryFlags::exec()
        } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
            PTEntryFlags::data()
        } else {
            PTEntryFlags::data_ro()
        };

        let vregion = MemoryRegion::new(vaddr_start, segment_len);
        pgtable
            .map_region(vregion, phys, flags)
            .expect("Failed to map kernel ELF segment");

        phys = phys + segment_len;
    }

    // Map the IGVM parameters if present.
    if let Some(ref igvm_params) = igvm_param_info.igvm_params {
        let vregion = MemoryRegion::new(igvm_param_info.virt_addr, igvm_params.size());
        pgtable
            .map_region(
                vregion,
                PhysAddr::from(launch_info.igvm_params_phys_addr),
                PTEntryFlags::data(),
            )
            .expect("Failed to map IGVM parameters");
    }

    // Map subsequent heap area.
    let heap_vregion = MemoryRegion::new(
        VirtAddr::from(launch_info.heap_area_virt_start),
        launch_info.heap_area_size as usize,
    );
    pgtable
        .map_region(
            heap_vregion,
            PhysAddr::from(launch_info.heap_area_phys_start),
            PTEntryFlags::data(),
        )
        .expect("Failed to map heap");

    init_global_ranges();

    Ok(pgtable)
}

fn invalidate_boot_memory_region(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    region: MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    // Caller must ensure the memory region's starting address is page-aligned
    let aligned_region = MemoryRegion::new(region.start(), page_align_up(region.len()));
    log::info!("Invalidating boot region {aligned_region:#018x}");

    if !aligned_region.is_empty() {
        platform.validate_physical_page_range(aligned_region, PageValidateOp::Invalidate)?;

        if config.page_state_change_required() {
            platform.page_state_change(
                aligned_region,
                PageSize::Regular,
                PageStateChangeOp::Shared,
            )?;
        }
    }

    Ok(())
}

pub fn invalidate_early_boot_memory(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    launch_info: &KernelLaunchInfo,
) -> Result<(), SvsmError> {
    // Early boot memory must be invalidated after changing to the SVSM page
    // page table to avoid invalidating page tables currently in use.  Always
    // invalidate stage 2 memory, unless firmware is loaded into low memory.
    // Also invalidate the boot data if required.
    if !config.fw_in_low_memory() {
        let lowmem_region = MemoryRegion::from_addresses(
            PhysAddr::from(0u64),
            PhysAddr::from(u64::from(LOWMEM_END)),
        );
        invalidate_boot_memory_region(platform, config, lowmem_region)?;
    }

    let stage2_base = PhysAddr::from(launch_info.stage2_start);
    let stage2_end = PhysAddr::from(launch_info.stage2_end);
    let stage2_region = MemoryRegion::from_addresses(stage2_base, stage2_end);
    invalidate_boot_memory_region(platform, config, stage2_region)?;

    if config.invalidate_boot_data() {
        let kernel_elf_size =
            launch_info.kernel_elf_stage2_virt_end - launch_info.kernel_elf_stage2_virt_start;
        let kernel_elf_region = MemoryRegion::new(
            PhysAddr::new(launch_info.kernel_elf_stage2_virt_start.try_into().unwrap()),
            kernel_elf_size.try_into().unwrap(),
        );
        invalidate_boot_memory_region(platform, config, kernel_elf_region)?;

        let kernel_fs_size = launch_info.kernel_fs_end - launch_info.kernel_fs_start;
        if kernel_fs_size > 0 {
            let kernel_fs_region = MemoryRegion::new(
                PhysAddr::new(launch_info.kernel_fs_start.try_into().unwrap()),
                kernel_fs_size.try_into().unwrap(),
            );
            invalidate_boot_memory_region(platform, config, kernel_fs_region)?;
        }

        if launch_info.stage2_igvm_params_size > 0 {
            let igvm_params_region = MemoryRegion::new(
                PhysAddr::new(launch_info.stage2_igvm_params_phys_addr.try_into().unwrap()),
                launch_info.stage2_igvm_params_size as usize,
            );
            invalidate_boot_memory_region(platform, config, igvm_params_region)?;
        }
    }

    Ok(())
}
