// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::PhysAddr;
use crate::config::SvsmConfig;
use crate::error::SvsmError;
use crate::platform::{PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::types::PageSize;
use crate::utils::{MemoryRegion, page_align_up};
use bootlib::kernel_launch::{KernelLaunchInfo, LOWMEM_END};

use alloc::vec::Vec;

fn invalidate_boot_memory_region(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    region: MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    // Caller must ensure the memory region's starting address is page-aligned
    let aligned_region = MemoryRegion::new(region.start(), page_align_up(region.len()));
    log::info!("Invalidating boot region {aligned_region:#018x}");

    if !aligned_region.is_empty() {
        // SAFETY: invalidating memory cannot cause UB.
        unsafe {
            platform.validate_physical_page_range(aligned_region, PageValidateOp::Invalidate)
        }?;

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

pub fn enumerate_early_boot_regions(
    config: &SvsmConfig<'_>,
    launch_info: &KernelLaunchInfo,
) -> Vec<MemoryRegion<PhysAddr>> {
    let mut regions = Vec::new();

    // Early boot memory must be invalidated after changing to the SVSM page
    // page table to avoid invalidating page tables currently in use.  Always
    // invalidate stage 2 memory, unless firmware is loaded into low memory.
    // Also invalidate the boot data if required.
    if !config.fw_in_low_memory() {
        regions.push(MemoryRegion::from_addresses(
            PhysAddr::from(0u64),
            PhysAddr::from(u64::from(LOWMEM_END)),
        ));
    }

    // All stage2 memory is contiguous, and is bounded by the stage2 image
    // at the base and the filesystem at the end.
    let stage2_area_base = PhysAddr::from(launch_info.stage2_start);
    let stage2_area_end = PhysAddr::new(launch_info.kernel_fs_end.try_into().unwrap());
    regions.push(MemoryRegion::from_addresses(
        stage2_area_base,
        stage2_area_end,
    ));

    regions
}

pub fn invalidate_early_boot_memory(
    platform: &dyn SvsmPlatform,
    config: &SvsmConfig<'_>,
    regions: &[MemoryRegion<PhysAddr>],
) -> Result<(), SvsmError> {
    for region in regions {
        invalidate_boot_memory_region(platform, config, *region)?;
    }

    Ok(())
}
