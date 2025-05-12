// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 IBM Corp
//
// Author: Dov Murik <dovmurik@linux.ibm.com>

pub mod apic;
pub mod attest;
pub mod core;
pub mod errors;
#[cfg(all(feature = "vtpm", not(test)))]
pub mod vtpm;

extern crate alloc;
use crate::vmm::GuestRegister;
use alloc::vec::Vec;
use cpuarch::vmsa::VMSA;

// SVSM protocols
pub const SVSM_CORE_PROTOCOL: u32 = 0;
pub const SVSM_ATTEST_PROTOCOL: u32 = 1;
pub const SVSM_VTPM_PROTOCOL: u32 = 2;
pub const SVSM_APIC_PROTOCOL: u32 = 3;

#[derive(Debug, Default, Clone, Copy)]
pub struct RequestParams {
    sev_features: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
}

impl RequestParams {
    pub fn from_vmsa(vmsa: &VMSA) -> Self {
        RequestParams {
            sev_features: vmsa.sev_features,
            rcx: vmsa.rcx,
            rdx: vmsa.rdx,
            r8: vmsa.r8,
        }
    }

    pub fn capture(&self, regs: &mut Vec<GuestRegister>) {
        regs.push(GuestRegister::X64Rcx(self.rcx));
        regs.push(GuestRegister::X64Rdx(self.rdx));
        regs.push(GuestRegister::X64R8(self.r8));
    }
}
