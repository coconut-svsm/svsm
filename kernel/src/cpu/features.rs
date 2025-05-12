// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::platform::SvsmPlatform;

const X86_FEATURE_PGE: u32 = 13;
const X86_FEATURE_SMEP: u32 = 7;
const X86_FEATURE_SMAP: u32 = 20;
const X86_FEATURE_UMIP: u32 = 2;

pub fn cpu_has_pge(platform: &dyn SvsmPlatform) -> bool {
    platform
        .cpuid(0x0000_0001, 0)
        .map_or_else(|| false, |c| (c.edx >> X86_FEATURE_PGE) & 1 == 1)
}

pub fn cpu_has_smep(platform: &dyn SvsmPlatform) -> bool {
    platform
        .cpuid(0x0000_0007, 0)
        .map_or_else(|| false, |c| (c.ebx >> X86_FEATURE_SMEP & 1) == 1)
}

pub fn cpu_has_smap(platform: &dyn SvsmPlatform) -> bool {
    platform
        .cpuid(0x0000_0007, 0)
        .map_or_else(|| false, |c| (c.ebx >> X86_FEATURE_SMAP & 1) == 1)
}

pub fn cpu_has_umip(platform: &dyn SvsmPlatform) -> bool {
    platform
        .cpuid(0x0000_0007, 0)
        .map_or_else(|| false, |c| (c.ecx >> X86_FEATURE_UMIP & 1) == 1)
}
