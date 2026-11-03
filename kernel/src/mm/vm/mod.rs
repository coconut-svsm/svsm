// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

mod context;
mod mapping;
mod range;

pub use context::{ContextVMR, ContextVMRMapping};
pub use mapping::{
    Mapping, RawAllocMapping, VMFileMapping, VMFileMappingFlags, VMKernelStack, VMM, VMMAdapter,
    VMPhysMem, VMReserved, VMalloc, VirtualMapping,
};
pub use range::{VMR, VMR_GRANULE, VMRMapping};
