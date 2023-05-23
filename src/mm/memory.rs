// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, PhysAddr};
use crate::cpu::percpu::PERCPU_VMSAS;
use crate::error::SvsmError;
use crate::fw_cfg::{FwCfg, MemoryRegion};
use crate::kernel_launch::KernelLaunchInfo;
use crate::locking::RWLock;
use alloc::vec::Vec;
use log;

use super::pagetable::LAUNCH_VMSA_ADDR;

static MEMORY_MAP: RWLock<Vec<MemoryRegion>> = RWLock::new(Vec::new());

pub fn init_memory_map(fwcfg: &FwCfg, launch_info: &KernelLaunchInfo) -> Result<(), SvsmError> {
    let mut regions = fwcfg.get_memory_regions()?;

    // Remove SVSM memory from guest memory map
    let mut i = 0;
    while i < regions.len() {
        // Check if the region overlaps with SVSM memory.
        let region = regions[i];
        if !region.overlaps(
            launch_info.kernel_region_phys_start,
            launch_info.kernel_region_phys_end,
        ) {
            // Check the next region.
            i += 1;
            continue;
        }

        // 1. Remove the region.
        regions.remove(i);

        // 2. Insert a region up until the start of SVSM memory (if non-empty).
        let region_before_start = region.start;
        let region_before_end = launch_info.kernel_region_phys_start;
        if region_before_start < region_before_end {
            regions.insert(
                i,
                MemoryRegion {
                    start: region_before_start,
                    end: region_before_end,
                },
            );
            i += 1;
        }

        // 3. Insert a region up after the end of SVSM memory (if non-empty).
        let region_after_start = launch_info.kernel_region_phys_end;
        let region_after_end = region.end;
        if region_after_start < region_after_end {
            regions.insert(
                i,
                MemoryRegion {
                    start: region_after_start,
                    end: region_after_end,
                },
            );
            i += 1;
        }
    }

    log::info!("Guest Memory Regions:");
    for r in regions.iter() {
        log::info!("  {:018x}-{:018x}", r.start, r.end);
    }

    let mut map = MEMORY_MAP.lock_write();
    *map = regions;

    Ok(())
}

pub fn valid_phys_address(paddr: PhysAddr) -> bool {
    let page_addr = paddr.page_align();
    let addr = paddr.bits() as u64;

    if PERCPU_VMSAS.exists(page_addr) {
        return false;
    }
    if page_addr == *LAUNCH_VMSA_ADDR {
        return false;
    }

    MEMORY_MAP
        .lock_read()
        .iter()
        .any(|region| addr >= region.start && addr < region.end)
}
