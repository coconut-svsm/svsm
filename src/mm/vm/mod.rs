// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

mod mapping;

pub use mapping::{
    Mapping, RawAllocMapping, VMKernelStack, VMMAdapter, VMPhysMem, VMReserved, VMalloc,
    VirtualMapping, VMM,
};
