// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

mod mapping;
mod range;

use crate::mm::pagetable::PTEntryFlags;
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

impl VMFlags {
    /// The flags describing the access to a mapping, as opposed to those
    /// describing where and how it is placed.
    pub fn access_mask() -> Self {
        Self::Read | Self::Write | Self::Execute
    }

    /// Returns these flags with the access they describe replaced by the one
    /// `access` describes. Flags outside [`VMFlags::access_mask()`] are
    /// preserved, so that changing the access of a mapping does not change
    /// anything else about it.
    ///
    /// # Arguments
    ///
    /// * `access` - The flags to take the access from.
    ///
    /// # Returns
    ///
    /// The resulting flags.
    pub fn with_access(self, access: Self) -> Self {
        self.difference(Self::access_mask())
            .union(access.intersection(Self::access_mask()))
    }

    /// The page-table flags enforcing the access these flags describe.
    ///
    /// # Returns
    ///
    /// The page-table flags to map pages of a mapping with this access with.
    pub fn page_prot(self) -> PTEntryFlags {
        match (self.contains(Self::Write), self.contains(Self::Execute)) {
            (false, false) => PTEntryFlags::NX,
            (false, true) => PTEntryFlags::empty(),
            (true, false) => PTEntryFlags::WRITABLE | PTEntryFlags::NX,
            (true, true) => PTEntryFlags::WRITABLE,
        }
    }
}

pub use mapping::{
    Mapping, RawAllocMapping, VMFileMapping, VMKernelStack, VMM, VMMAdapter, VMPhysMem, VMReserved,
    VMalloc, VirtualMapping,
};
pub use range::{VMR, VMR_GRANULE, VMRMapping};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_prot() {
        // Write access is granted explicitly, execute access by the absence
        // of the NX flag. Read access has no page-table representation.
        assert_eq!(VMFlags::Read.page_prot().bits(), PTEntryFlags::NX.bits());
        assert_eq!(
            VMFlags::Write.page_prot().bits(),
            (PTEntryFlags::WRITABLE | PTEntryFlags::NX).bits()
        );
        assert_eq!(
            VMFlags::Execute.page_prot().bits(),
            PTEntryFlags::empty().bits()
        );
        assert_eq!(
            (VMFlags::Write | VMFlags::Execute).page_prot().bits(),
            PTEntryFlags::WRITABLE.bits()
        );
    }

    #[test]
    fn test_with_access() {
        // The access is replaced, everything else is kept.
        let flags = VMFlags::Private | VMFlags::Fixed | VMFlags::Write;

        let ro = flags.with_access(VMFlags::Read);
        assert!(ro.contains(VMFlags::Private | VMFlags::Fixed | VMFlags::Read));
        assert!(!ro.contains(VMFlags::Write));

        // Placement flags of the new access are ignored.
        let rw = ro.with_access(VMFlags::Write);
        assert!(rw.contains(VMFlags::Private | VMFlags::Fixed | VMFlags::Write));
        assert!(!rw.contains(VMFlags::Read));
    }
}
