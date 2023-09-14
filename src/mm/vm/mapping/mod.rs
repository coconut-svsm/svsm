// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod api;
pub mod kernel_stack;
pub mod phys_mem;
pub mod rawalloc;
pub mod vmalloc;

pub use api::{Mapping, VMMAdapter, VirtualMapping, VMM};
pub use kernel_stack::VMKernelStack;
pub use phys_mem::VMPhysMem;
pub use rawalloc::RawAllocMapping;
pub use vmalloc::VMalloc;
