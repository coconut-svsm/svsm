// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::platform::SvsmPlatform;

const X86_FEATURE_PGE: u32 = 13;

pub fn cpu_has_pge(platform: &dyn SvsmPlatform) -> bool {
    let ret = platform.cpuid(0x00000001);

    match ret {
        None => false,
        Some(c) => (c.edx >> X86_FEATURE_PGE) & 1 == 1,
    }
}
