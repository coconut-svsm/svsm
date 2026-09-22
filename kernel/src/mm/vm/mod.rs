// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

mod mapping;
mod range;
mod shared;

pub use mapping::{
    Mapping, RawAllocMapping, VMFileMapping, VMFileMappingFlags, VMKernelStack, VMPhysMem,
    VMReserved, VMalloc, VirtualMapping,
};
pub use range::{PrivateVmAllocator, VMR_GRANULE, VmAllocator, VmRange, Vmr, VmrMapping};
pub use shared::TaskVmAllocator;
