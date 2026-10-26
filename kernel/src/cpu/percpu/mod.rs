// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Advanced Micro Devices, Inc.
//
// Author: Joerg Roedel <joerg.roedel@amd.com>

#[macro_use]
mod key;
mod legacy;

pub use key::PerCpuKey;
#[doc(hidden)]
pub use key::PerCpuStorage;
pub use legacy::{
    GuestVmsaRef, PERCPU_AREAS, PERCPU_SHARED_INDEX_OFFSET, PERCPU_VMSAS, PerCpu, PerCpuAreas,
    PerCpuShared, PerCpuVmsas, VmsaRegistryEntry, cpu_idle_loop, current_task, this_cpu,
    try_this_cpu, with_pgtable, with_pgtable_mut,
};
