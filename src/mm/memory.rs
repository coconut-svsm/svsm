// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::percpu::PERCPU_VMSAS;
use crate::fw_cfg::{FwCfg, MemoryRegion};
use crate::kernel_launch::KernelLaunchInfo;
use crate::locking::RWLock;
use crate::types::PhysAddr;
use crate::utils::page_align;
use alloc::vec::Vec;
use log;

static MEMORY_MAP: RWLock<Vec<MemoryRegion>> = RWLock::new(Vec::new());

pub fn init_memory_map(fwcfg: &FwCfg, launch_info: &KernelLaunchInfo) -> Result<(), ()> {
    let mut regions = fwcfg.get_memory_regions()?;

    // Remove SVSM memory from guest memory map
    for mut region in regions.iter_mut() {
        if (launch_info.kernel_region_phys_start > region.start)
            && (launch_info.kernel_region_phys_start < region.end)
        {
            region.end = launch_info.kernel_region_phys_start;
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
    let page_addr = page_align(paddr);
    let addr = paddr as u64;

    if PERCPU_VMSAS.exists(page_addr) {
        return false;
    }

    MEMORY_MAP
        .lock_read()
        .iter()
        .any(|region| addr >= region.start && addr < region.end)
}
