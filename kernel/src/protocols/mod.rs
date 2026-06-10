// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 IBM Corp
//
// Author: Dov Murik <dovmurik@linux.ibm.com>

pub mod apic;
pub mod attest;
pub mod core;
pub mod errors;
pub mod ocp;
#[cfg(all(feature = "uefivars", not(test)))]
pub mod uefivars;
#[cfg(all(feature = "vtpm", not(test)))]
pub mod vtpm;

use cpuarch::vmsa::VMSA;

// SVSM protocols
pub const SVSM_CORE_PROTOCOL: u32 = 0;
pub const SVSM_ATTEST_PROTOCOL: u32 = 1;
pub const SVSM_VTPM_PROTOCOL: u32 = 2;
pub const SVSM_APIC_PROTOCOL: u32 = 3;
pub const SVSM_UEFI_MM_PROTOCOL: u32 = 4;

#[derive(Debug, Default, Clone, Copy)]
pub struct RequestParams {
    sev_features: u64,
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
}

impl RequestParams {
    pub fn from_vmsa(vmsa: &VMSA) -> Self {
        RequestParams {
            sev_features: vmsa.sev_features,
            rcx: vmsa.rcx,
            rdx: vmsa.rdx,
            r8: vmsa.r8,
            r9: vmsa.r9,
        }
    }

    pub fn capture(&self, res: &mut RequestOutput) {
        res.rcx = Some(self.rcx);
        res.rdx = Some(self.rdx);
        res.r8 = Some(self.r8);
        res.r9 = Some(self.r9);
    }
}

/// Output registers as per the SVSM protocol ABI.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestOutput {
    rax: Option<u64>,
    rcx: Option<u64>,
    rdx: Option<u64>,
    r8: Option<u64>,
    r9: Option<u64>,
}

impl RequestOutput {
    pub const fn new() -> Self {
        Self {
            rax: None,
            rcx: None,
            rdx: None,
            r8: None,
            r9: None,
        }
    }

    pub fn set_rax(&mut self, rax: u64) {
        self.rax = Some(rax);
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn copy_to_vmsa(&self, vmsa: &mut VMSA) {
        if let Some(val) = self.rax {
            vmsa.rax = val;
        }
        if let Some(val) = self.rcx {
            vmsa.rcx = val;
        }
        if let Some(val) = self.rdx {
            vmsa.rdx = val;
        }
        if let Some(val) = self.r8 {
            vmsa.r8 = val;
        }
        if let Some(val) = self.r9 {
            vmsa.r9 = val;
        }
    }
}
