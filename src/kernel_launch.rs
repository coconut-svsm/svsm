// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#[derive(Copy, Clone)]
pub struct KernelLaunchInfo {
    pub kernel_region_phys_start: u64,
    pub kernel_region_phys_end: u64,
    pub heap_area_phys_start: u64, // Start of trailing heap area within the physical memory region.
    pub kernel_region_virt_start: u64,
    pub heap_area_virt_start: u64, // Start of virtual heap area mapping.
    pub cpuid_page: u64,
    pub secrets_page: u64,
}

impl KernelLaunchInfo {
    pub fn heap_area_size(&self) -> u64 {
        self.kernel_region_phys_end - self.heap_area_phys_start
    }

    pub fn heap_area_virt_end(&self) -> u64 {
        self.heap_area_virt_start + self.heap_area_size()
    }
}
