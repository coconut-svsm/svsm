// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

mod mapping;
mod range;

pub use mapping::{
    Mapping, RawAllocMapping, ShadowStackInit, VMFileMapping, VMFileMappingFlags,
    VMKernelShadowStack, VMKernelStack, VMMAdapter, VMPhysMem, VMReserved, VMalloc, VirtualMapping,
    VMM,
};
pub use range::{VMRMapping, VMR, VMR_GRANULE};
