// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

use bitfield_struct::bitfield;

#[bitfield(u64, default = false)]
#[derive(PartialEq, Eq)]
pub struct Dr7 {
    /// Local breakpoint enable 0
    pub l0: bool,
    /// Global breakpoint enable 0
    pub g0: bool,
    /// Local breakpoint enable 1
    pub l1: bool,
    /// Global breakpoint enable 1
    pub g1: bool,
    /// Local breakpoint enable 2
    pub l2: bool,
    /// Global breakpoint enable 2
    pub g2: bool,
    /// Local breakpoint enable 3
    pub l3: bool,
    /// Global breakpoint enable 3
    pub g3: bool,
    /// Local-enable (legacy)
    pub le: bool,
    /// Global enable (legacy)
    pub ge: bool,
    /// Reserved bit (always set)
    pub rsvd10: bool,
    /// Restricted transactional memory
    pub rtm: bool,
    /// Reserved bit (always clear)
    rsvd12: bool,
    /// General detect enable
    pub gd: bool,
    /// Reserved bits (always clear)
    #[bits(2)]
    rsvd14: u8,
    /// Read/write 0
    #[bits(2)]
    pub rw0: u8,
    /// Length 0
    #[bits(2)]
    pub len0: u8,
    /// Read/write 1
    #[bits(2)]
    pub rw1: u8,
    /// Length 1
    #[bits(2)]
    pub len1: u8,
    /// Read/write 2
    #[bits(2)]
    pub rw2: u8,
    /// Length 2
    #[bits(2)]
    pub len2: u8,
    /// Read/write 3
    #[bits(2)]
    pub rw3: u8,
    /// Length 3
    #[bits(2)]
    pub len3: u8,
    unused: u32,
}

impl Dr7 {
    /// Mask of values that can be written into DR7
    pub const fn valid_mask() -> Self {
        Self::from_bits(u64::MAX)
            .with_rtm(false)
            .with_rsvd12(false)
            .with_rsvd14(0)
            .with_unused(0)
    }
}

impl Default for Dr7 {
    fn default() -> Self {
        // Default value of the register at reset
        Self::from_bits(0).with_rsvd10(true)
    }
}
