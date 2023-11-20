// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr};
use crate::mm::pagetable::PTEntryFlags;

use super::{Mapping, VirtualMapping};

/// Map physically contiguous memory
#[derive(Default, Debug, Clone, Copy)]
pub struct VMPhysMem {
    /// Physical base address to map
    base: PhysAddr,
    /// Number of bytes to map
    size: usize,
    /// Whether mapping is writable
    writable: bool,
}

impl VMPhysMem {
    /// Initialize new instance of [`VMPhysMem`]
    ///
    /// # Arguments
    ///
    /// * `base` - Physical base address to map
    /// * `size` - Number of bytes to map
    /// * `writable` - Whether mapping is writable
    ///
    /// # Returns
    ///
    /// New instance of [`VMPhysMem`]
    pub fn new(base: PhysAddr, size: usize, writable: bool) -> Self {
        VMPhysMem {
            base,
            size,
            writable,
        }
    }

    /// Initialize new [`Mapping`] with [`VMPhysMem`]
    ///
    /// # Arguments
    ///
    /// * `base` - Physical base address to map
    /// * `size` - Number of bytes to map
    /// * `writable` - Whether mapping is writable
    ///
    /// # Returns
    ///
    /// New [`Mapping`] containing [`VMPhysMem`]
    pub fn new_mapping(base: PhysAddr, size: usize, writable: bool) -> Mapping {
        Mapping::new(Self::new(base, size, writable))
    }
}

impl VirtualMapping for VMPhysMem {
    fn mapping_size(&self) -> usize {
        self.size
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        if offset < self.size {
            Some((self.base + offset).page_align())
        } else {
            None
        }
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        PTEntryFlags::NX
            | PTEntryFlags::ACCESSED
            | if self.writable {
                PTEntryFlags::WRITABLE | PTEntryFlags::DIRTY
            } else {
                PTEntryFlags::empty()
            }
    }
}
