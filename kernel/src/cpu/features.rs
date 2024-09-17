// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::platform::SvsmPlatform;

const X86_FEATURE_NX: u32 = 20;
const X86_FEATURE_PGE: u32 = 13;
const X86_FEATURE_SMEP: u32 = 7;
const X86_FEATURE_SMAP: u32 = 20;

pub fn cpu_has_nx(platform: &dyn SvsmPlatform) -> bool {
    let ret = platform.cpuid(0x80000001);

    match ret {
        None => false,
        Some(c) => (c.edx >> X86_FEATURE_NX) & 1 == 1,
    }
}

pub fn cpu_has_pge(platform: &dyn SvsmPlatform) -> bool {
    let ret = platform.cpuid(0x00000001);

    match ret {
        None => false,
        Some(c) => (c.edx >> X86_FEATURE_PGE) & 1 == 1,
    }
}

pub fn cpu_has_smep(platform: &dyn SvsmPlatform) -> bool {
    let ret = platform.cpuid(0x0000_0007);

    match ret {
        None => false,
        Some(c) => (c.ebx >> X86_FEATURE_SMEP & 1) == 1,
    }
}

pub fn cpu_has_smap(platform: &dyn SvsmPlatform) -> bool {
    let ret = platform.cpuid(0x0000_0007);

    match ret {
        None => false,
        Some(c) => (c.ebx >> X86_FEATURE_SMAP & 1) == 1,
    }
}
