// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

extern crate alloc;

use crate::cpu::percpu::vmsa_exists;
use crate::utils::page_align;
use crate::types::PhysAddr;
use crate::kernel_launch::KernelLaunchInfo;
use crate::fw_cfg::{FwCfg, MemoryRegion};
use crate::locking::RWLock;
use alloc::vec::Vec;
use log;

static MEMORY_MAP: RWLock<Vec<MemoryRegion>> = RWLock::new(Vec::new());


pub fn init_memory_map(fwcfg: &FwCfg, launch_info: &KernelLaunchInfo) -> Result<(),()> {
    let mut regions = fwcfg.get_memory_regions()?;

    // Remove SVSM memory from guest memory map
    for mut region in regions.iter_mut() {
        if (launch_info.kernel_start > region.start) &&
           (launch_info.kernel_start < region.end) {
               region.end = launch_info.kernel_start;
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

    if vmsa_exists(page_addr) {
        return false;
    }

    MEMORY_MAP.lock_read().iter()
        .any(|region| addr >= region.start && addr < region.end )
}
