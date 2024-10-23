// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod api;
pub mod file_mapping;
pub mod kernel_stack;
pub mod phys_mem;
pub mod rawalloc;
pub mod reserved;
pub mod shadow_stack;
pub mod vmalloc;

pub use api::{Mapping, VMMAdapter, VMPageFaultResolution, VirtualMapping, VMM};
pub use file_mapping::{VMFileMapping, VMFileMappingFlags};
pub use kernel_stack::VMKernelStack;
pub use phys_mem::VMPhysMem;
pub use rawalloc::RawAllocMapping;
pub use reserved::VMReserved;
pub use shadow_stack::{ShadowStackInit, VMKernelShadowStack};
pub use vmalloc::VMalloc;
