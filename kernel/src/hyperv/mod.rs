// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

pub mod hv;
pub mod msr;

pub use hv::*;
pub use msr::*;

use bitfield_struct::bitfield;

#[bitfield(u8)]
pub struct HvInputVtl {
    #[bits(4)]
    target_vtl: u8,
    use_target_vtl: bool,
    #[bits(3)]
    _rsvd_5_7: u8,
}

impl HvInputVtl {
    pub fn use_self() -> Self {
        Self::new()
    }

    pub fn use_vtl(vtl: u8) -> Self {
        Self::new().with_target_vtl(vtl).with_use_target_vtl(true)
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum HvRegisterName {
    VsmVpStatus = 0xD0003,
}

#[bitfield(u64)]
pub struct HvRegisterVsmVpStatus {
    #[bits(4)]
    pub active_vtl: u8,
    pub active_mbec_enabled: bool,
    #[bits(11)]
    _rsvd_5_15: u64,
    pub enabled_vtl_set: u16,
    _rsvd_32_63: u32,
}
