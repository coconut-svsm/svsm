// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::PhysAddr;
use crate::boot_params::BootParams;
use crate::error::SvsmError;
use crate::platform::{PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::utils::{MemoryRegion, page_align_up};
use bootdefs::kernel_launch::KernelLaunchInfo;
use bootdefs::kernel_launch::LOWMEM_END;

use alloc::vec::Vec;

fn invalidate_boot_memory_region(
    platform: &dyn SvsmPlatform,
    boot_params: &BootParams<'_>,
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

        if boot_params.page_state_change_required() {
            platform.page_state_change(aligned_region, PageStateChangeOp::Shared)?;
        }
    }

    Ok(())
}

pub fn enumerate_early_boot_regions(
    boot_params: &BootParams<'_>,
    launch_info: &KernelLaunchInfo,
) -> Vec<MemoryRegion<PhysAddr>> {
    let mut regions = Vec::new();

    // Early boot memory must be invalidated after changing to the SVSM page
    // page table to avoid invalidating page tables currently in use.  Always
    // invalidate stage 2 memory, unless firmware is loaded into low memory.
    // Also invalidate the boot data if required.
    if !boot_params.fw_in_low_memory() {
        regions.push(MemoryRegion::from_addresses(
            PhysAddr::from(0u64),
            PhysAddr::from(u64::from(LOWMEM_END)),
        ));
    }

    // All boot loader memory is contiguous, and is bounded by the boot loader
    // image at the base and the filesystem at the end.
    let bldr_area_base = PhysAddr::from(launch_info.bldr_start);
    let bldr_area_end = PhysAddr::new(launch_info.kernel_fs_end.try_into().unwrap());
    regions.push(MemoryRegion::from_addresses(bldr_area_base, bldr_area_end));

    regions
}

pub fn invalidate_early_boot_memory(
    platform: &dyn SvsmPlatform,
    boot_params: &BootParams<'_>,
    regions: &[MemoryRegion<PhysAddr>],
) -> Result<(), SvsmError> {
    for region in regions {
        invalidate_boot_memory_region(platform, boot_params, *region)?;
    }

    Ok(())
}
