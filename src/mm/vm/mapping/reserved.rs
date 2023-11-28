// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::PhysAddr;
use crate::mm::pagetable::PTEntryFlags;

use super::{Mapping, VirtualMapping};

/// Reserve a region of address space so that no other mapping will be
/// established there. The map function for this type will always return
/// `None`.
#[derive(Default, Debug, Clone, Copy)]
pub struct VMReserved {
    /// Size in bytes to reserve. Must be aligned to PAGE_SIZE
    size: usize,
}

impl VMReserved {
    /// Create new instance of VMReserved
    ///
    /// # Arguments
    ///
    /// * `size` - Number of bytes to reserve
    ///
    /// # Returns
    ///
    /// New instance of VMReserved
    pub fn new(size: usize) -> Self {
        VMReserved { size }
    }

    /// Create new [`Mapping`] of [`VMReserved`]
    ///
    /// # Arguments
    ///
    /// * `size` - Number of bytes to reserve
    ///
    /// # Returns
    ///
    /// New Mapping of VMReserved
    pub fn new_mapping(size: usize) -> Mapping {
        Mapping::new(Self::new(size))
    }
}

impl VirtualMapping for VMReserved {
    fn mapping_size(&self) -> usize {
        self.size
    }

    fn has_data(&self) -> bool {
        false
    }

    fn map(&self, _offset: usize) -> Option<PhysAddr> {
        None
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::WRITABLE | PTEntryFlags::DIRTY
    }
}
