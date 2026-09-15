// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

mod mapping;
mod range;

use bitflags::bitflags;

bitflags! {
    /// The access and placement of a virtual mapping.
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub struct VMFlags : u32 {
        /// Read access to the mapping
        const Read = 1 << 0;
        /// Write access to the mapping
        const Write = 1 << 1;
        /// Execute access to the mapping
        const Execute = 1 << 2;
        /// Map a private copy of the backing pages
        const Private = 1 << 3;
        /// Map at a fixed address
        const Fixed = 1 << 4;
    }
}

pub use mapping::{
    Mapping, RawAllocMapping, VMFileMapping, VMKernelStack, VMM, VMMAdapter, VMPhysMem, VMReserved,
    VMalloc, VirtualMapping,
};
pub use range::{VMR, VMR_GRANULE, VMRMapping};
