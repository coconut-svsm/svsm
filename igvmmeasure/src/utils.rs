// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use igvm::{IgvmFile, IgvmPlatformHeader};
use igvm_defs::IgvmPlatformType;


pub fn get_compatibility_mask(igvm: &IgvmFile, platform: IgvmPlatformType) -> Option<u32> {
    let mut compatibility_mask: Option<u32> = None;
    for pl in igvm.platforms() {
        let IgvmPlatformHeader::SupportedPlatform(supported) = pl;
        if supported.platform_type == platform {
            compatibility_mask = Some(supported.compatibility_mask);
            break;
        }
    }
    compatibility_mask
}
