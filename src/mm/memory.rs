// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

extern crate alloc;

use crate::types::PhysAddr;
use crate::kernel_launch::KernelLaunchInfo;
use crate::fw_cfg::{FwCfg, MemoryRegion};
use alloc::vec::Vec;
use log;

static mut MEMORY_MAP: Vec<MemoryRegion> = Vec::new();


pub fn init_memory_map(fwcfg: &FwCfg, launch_info: &KernelLaunchInfo) -> Result<(),()> {
    let mut regions = fwcfg.get_memory_regions()?;

    // Remove SVSM memory from guest memory map
    for i in 0..regions.len() {
        if (launch_info.kernel_start > regions[i].start) &&
           (launch_info.kernel_start < regions[i].end) {
               regions[i].end = launch_info.kernel_start;
           }
    }

    log::info!("Guest Memory Regions:");
    for i in 0..regions.len() {
        log::info!("  {:018x}-{:018x}", regions[i].start, regions[i].end);
    }

    unsafe { MEMORY_MAP = regions; }

    Ok(())
}

pub fn valid_phys_address(addr: PhysAddr) -> bool {
    let len = unsafe { MEMORY_MAP.len() };
    for i in 0..len {
        let start: PhysAddr = unsafe {MEMORY_MAP[i].start.try_into().unwrap() };
        let end: PhysAddr = unsafe { MEMORY_MAP[i].end.try_into().unwrap() };

        if (addr >= start) && (addr <  end) {
            return true;
        }
    }

    return false;
}
