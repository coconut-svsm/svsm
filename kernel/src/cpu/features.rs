// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::platform::SvsmPlatform;

const X86_FEATURE_PGE: u32 = 13;
const X86_FEATURE_PCID: u32 = 17;
const X86_FEATURE_SMEP: u32 = 7;
const X86_FEATURE_SMAP: u32 = 20;
const X86_FEATURE_UMIP: u32 = 2;

pub fn cpu_has_pge(platform: &dyn SvsmPlatform) -> bool {
    platform
        .cpuid(0x0000_0001, 0)
        .map_or_else(|| false, |c| (c.edx >> X86_FEATURE_PGE) & 1 == 1)
}

pub fn cpu_has_pcid(platform: &dyn SvsmPlatform) -> bool {
    platform
        .cpuid(0x0000_0001, 0)
        .map_or_else(|| false, |c| (c.ecx >> X86_FEATURE_PCID) & 1 == 1)
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

#[cfg(test)]
mod tests {
    use crate::cpu::features::cpu_has_pcid;
    use crate::platform::SVSM_PLATFORM;

    // Test if PCID feature available from host CPU through hypervisor.
    // If it isn't available, prints nothing and continues with the text.
    //
    // Note: `--nocc` test argument on QEMU which employs TCG accelerator
    // seems doesn't support emulation of this feature at the moment.
    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn check_cpu_has_pcid() {
        let has_pcid = cpu_has_pcid(*SVSM_PLATFORM);
        log::info!("PCID supported: {has_pcid}");
    }
}
