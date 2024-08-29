// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, PhysAddr};
use crate::config::SvsmConfig;
use crate::cpu::percpu::PERCPU_VMSAS;
use crate::error::SvsmError;
use crate::locking::RWLock;
use crate::utils::MemoryRegion;
use alloc::vec::Vec;
use bootlib::kernel_launch::KernelLaunchInfo;

use super::pagetable::LAUNCH_VMSA_ADDR;

/// Global memory map containing various memory regions.
static MEMORY_MAP: RWLock<Vec<MemoryRegion<PhysAddr>>> = RWLock::new(Vec::new());

pub fn get_memory_region_from_map(idx: usize) -> MemoryRegion<PhysAddr> {
    let regions = MEMORY_MAP.lock_read();
    regions[idx]
}

pub fn get_memory_map_len() -> usize {
    MEMORY_MAP.lock_read().len()
}

/// Initializes the global memory map based on the provided configuration
/// and kernel launch information.
///
/// # Arguments
///
/// * `config` - A reference to the [`SvsmConfig`] containing memory region
///   information.
/// * `launch_info` - A reference to the [`KernelLaunchInfo`] containing
///   information about the kernel region.
///
/// # Returns
///
/// Returns `Ok(())` if the memory map is successfully initialized, otherwise
/// returns an error of type `SvsmError`.
pub fn init_memory_map(
    config: &SvsmConfig<'_>,
    launch_info: &KernelLaunchInfo,
) -> Result<(), SvsmError> {
    let mut regions = config.get_memory_regions()?;
    let kernel_start = PhysAddr::from(launch_info.kernel_region_phys_start);
    let kernel_end = PhysAddr::from(launch_info.kernel_region_phys_end);
    let kernel_region = MemoryRegion::from_addresses(kernel_start, kernel_end);
    log::info!("regions: {:?}",regions);

    // Remove SVSM memory from guest memory map
    let mut i = 0;
    while i < regions.len() {
        // Check if the region overlaps with SVSM memory.
        let region = regions[i];
        if !region.overlap(&kernel_region) {
            // Check the next region.

            i += 1;
            continue;
        }

        // 1. Remove the region.
        regions.remove(i);

        // 2. Insert a region up until the start of SVSM memory (if non-empty).
        let region_before_start = region.start();
        let region_before_end = kernel_region.start();
        if region_before_start < region_before_end {
            regions.insert(
                i,
                MemoryRegion::from_addresses(region_before_start, region_before_end),
            );
            i += 1;
        }

        // 3. Insert a region up after the end of SVSM memory (if non-empty).
        let region_after_start = kernel_region.end();
        let region_after_end = region.end();
        if region_after_start < region_after_end {
            regions.insert(
                i,
                MemoryRegion::from_addresses(region_after_start, region_after_end),
            );
            i += 1;
        }
    }
    //At this point we can be sure that regions does not contain any kernel memory
   /* let mut total_size = 0;
    i = 0;
    while i < regions.len() {
        let region = regions[i];
        total_size += region.end() - region.start();
        i+=1;
    }*/
    //let memory_limit = 1 * 1024 * 1024 * 1024;
    //if total_size <= memory_limit {
    //    panic!("Not enough memory given to CVM");
    //}
    /*i = 0;
    let mut current_size = 0;
    while i < regions.len() {
        let region = regions[i];
        let start = region.start();
        let end = region.end();
        if (end-start) - current_size > 0 {
doom emacs change file
    }
    }*/
    //regions.remove(2);
   
    //log::info!("Sum Region Size: {}", total_size);

   // log::info!("Guest Memory Regions:");
    for r in regions.iter() {
    log::info!("{:018x}-{:018x}", r.start(), r.end()); }

    log::info!("regions:{:?}",regions);
    //panic!();
    let mut map = MEMORY_MAP.lock_write();
    *map = regions;

    Ok(())
}

/// Returns `true` if the provided physical address `paddr` is valid, i.e.
/// it is within the configured memory regions, otherwise returns `false`.
pub fn valid_phys_address(paddr: PhysAddr) -> bool {
    let page_addr = paddr.page_align();

    if PERCPU_VMSAS.exists(page_addr) {
        return false;
    }
    if page_addr == LAUNCH_VMSA_ADDR {
        return false;
    }

    MEMORY_MAP
        .lock_read()
        .iter()
        .any(|region| region.contains(paddr))
}

/// The starting address of the ISA range.
const ISA_RANGE_START: PhysAddr = PhysAddr::new(0xa0000);

/// The ending address of the ISA range.
const ISA_RANGE_END: PhysAddr = PhysAddr::new(0x100000);

/// Returns `true` if the provided physical address `paddr` is writable,
/// otherwise returns `false`.
pub fn writable_phys_addr(paddr: PhysAddr) -> bool {
    // The ISA range is not writable
    if paddr >= ISA_RANGE_START && paddr < ISA_RANGE_END {
        return false;
    }

    valid_phys_address(paddr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn test_valid_phys_address() {
        let start = PhysAddr::new(0x1000);
        let end = PhysAddr::new(0x2000);
        let region = MemoryRegion::from_addresses(start, end);

        MEMORY_MAP.lock_write().push(region);

        // Inside the region
        assert!(valid_phys_address(PhysAddr::new(0x1500)));
        // Outside the region
        assert!(!valid_phys_address(PhysAddr::new(0x3000)));
    }
}
