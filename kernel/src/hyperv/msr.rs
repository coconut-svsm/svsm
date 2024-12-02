// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum HyperVMsr {
    GuestOSID = 0x40000000,
    Hypercall = 0x40000001,
}

impl From<HyperVMsr> for u32 {
    fn from(msr: HyperVMsr) -> Self {
        msr as u32
    }
}
