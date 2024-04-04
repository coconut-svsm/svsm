// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use igvm::{IgvmFile, IgvmPlatformHeader};
use igvm_defs::IgvmPlatformType;

pub fn get_policy(igvm: &IgvmFile, compatibility_mask: u32) -> Option<u64> {
    let mut policy: Option<u64> = None;
    for init in igvm.initializations() {
        if let igvm::IgvmInitializationHeader::GuestPolicy {
            policy: guest_policy,
            compatibility_mask: guest_cm,
        } = init
        {
            if (compatibility_mask & guest_cm) != 0 {
                policy = Some(*guest_policy);
                break;
            }
        }
    }
    policy
}

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
