// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::config::SvsmConfig;
use crate::error::SvsmError;
use crate::igvm_params::IgvmParams;
use crate::mm::pagetable::{PTEntryFlags, PageTable};
use crate::mm::{PageBox, PerCPUPageMappingGuard};
use crate::platform::{PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::types::{PageSize, PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::{align_down, page_align, zero_mem_region, MemoryRegion};
use bootlib::kernel_launch::KernelLaunchInfo;
use core::cmp::min;

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

    pgtable.load();

    Ok(pgtable)
}

fn scrub_phys_memory_region(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let mut start = region.start();
    let mut maxlen_4k = 512 * PAGE_SIZE; // 2M
    let mut maxlen_2m = 512 * PAGE_SIZE_2M; // 1G
    let region_end_4k = region.end().page_align_up();
    let region_end_2m = region.end().align_up(PAGE_SIZE_2M);

    while start < region.end() {
        let mut map_start = start.page_align();
        let (mapping, map_end) = if maxlen_4k == 0 && maxlen_2m == 0 {
            // No more space for temporary mappings
            return Err(SvsmError::Mem);
        } else if (maxlen_4k > 0 && (region_end_4k - map_start) < PAGE_SIZE_2M) || maxlen_2m == 0 {
            // Use 4K mappings if
            // - The mapping size < a 2M huge page, or
            // - There is no space for 2M temporary mappings
            let map_end = min(map_start + maxlen_4k, region_end_4k);
            match PerCPUPageMappingGuard::create(map_start, map_end, 0) {
                Ok(m) => (m, map_end),
                Err(SvsmError::Mem) => {
                    maxlen_4k = page_align((map_end - map_start) >> 1);
                    continue;
                }
                Err(e) => return Err(e),
            }
        } else {
            // Use 2M mappings if
            // - The mapping size >= a 2M huge page, or
            // - There is no space for 4K temporary mappings
            map_start = start.align_down(PAGE_SIZE_2M);
            let map_end = min(map_start + maxlen_2m, region_end_2m);
            match PerCPUPageMappingGuard::create(map_start, map_end, PAGE_SHIFT_2M - PAGE_SHIFT) {
                Ok(m) => (m, map_end),
                Err(SvsmError::Mem) => {
                    maxlen_2m = align_down((map_end - map_start) >> 1, PAGE_SIZE_2M);
                    continue;
                }
                Err(e) => return Err(e),
            }
        };
        let off = start - map_start;
        let len = min(map_end, region.end()) - map_start;
        zero_mem_region(mapping.virt_addr() + off, mapping.virt_addr() + len);
        start = map_end;
    }
    Ok(())
}

fn clean_up_boot_memory_region(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    region: MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    log::info!(
        "Cleaning up boot region {:018x}-{:018x}",
        region.start(),
        region.end()
    );

    if !region.is_empty() {
        // Some platforms (such as TDP) do not need page invalidation.
        // Scrub the memory region first to make sure its content is
        // always at least wiped.
        scrub_phys_memory_region(region)?;
        platform.validate_physical_page_range(region, PageValidateOp::Invalidate)?;

        if config.page_state_change_required() {
            platform.page_state_change(region, PageSize::Regular, PageStateChangeOp::Shared)?;
        }
    }

    Ok(())
}

pub fn clean_up_early_boot_memory(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    launch_info: &KernelLaunchInfo,
) -> Result<(), SvsmError> {
    // Early boot memory must be cleaned up after changing to the SVSM page
    // page table to avoid destroying page tables currently in use.  Always
    // clean up stage 2 memory, unless firmware is loaded into low memory.
    // Also clean up the boot data if required.
    if !config.fw_in_low_memory() {
        let lowmem_region = MemoryRegion::new(PhysAddr::null(), 640 * 1024);
        clean_up_boot_memory_region(platform, config, lowmem_region)?;
    }

    let stage2_base = PhysAddr::from(launch_info.stage2_start);
    let stage2_end = PhysAddr::from(launch_info.stage2_end);
    let stage2_region = MemoryRegion::from_addresses(stage2_base, stage2_end);
    clean_up_boot_memory_region(platform, config, stage2_region)?;

    if config.clean_up_boot_data() {
        let kernel_elf_size =
            launch_info.kernel_elf_stage2_virt_end - launch_info.kernel_elf_stage2_virt_start;
        let kernel_elf_region = MemoryRegion::new(
            PhysAddr::new(launch_info.kernel_elf_stage2_virt_start.try_into().unwrap()),
            kernel_elf_size.try_into().unwrap(),
        );
        clean_up_boot_memory_region(platform, config, kernel_elf_region)?;

        let kernel_fs_size = launch_info.kernel_fs_end - launch_info.kernel_fs_start;
        if kernel_fs_size > 0 {
            let kernel_fs_region = MemoryRegion::new(
                PhysAddr::new(launch_info.kernel_fs_start.try_into().unwrap()),
                kernel_fs_size.try_into().unwrap(),
            );
            clean_up_boot_memory_region(platform, config, kernel_fs_region)?;
        }

        if launch_info.stage2_igvm_params_size > 0 {
            let igvm_params_region = MemoryRegion::new(
                PhysAddr::new(launch_info.stage2_igvm_params_phys_addr.try_into().unwrap()),
                launch_info.stage2_igvm_params_size as usize,
            );
            clean_up_boot_memory_region(platform, config, igvm_params_region)?;
        }
    }

    Ok(())
}
