// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::PhysAddr;
use crate::utils::MemoryRegion;
use bootlib::kernel_launch::KernelLaunchInfo;

pub fn new_kernel_region(launch_info: &KernelLaunchInfo) -> MemoryRegion<PhysAddr> {
    let start = PhysAddr::from(launch_info.kernel_region_phys_start);
    let end = PhysAddr::from(launch_info.kernel_region_phys_end);
    MemoryRegion::from_addresses(start, end)
}
