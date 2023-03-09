// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#[derive(Copy, Clone)]
pub struct KernelLaunchInfo {
    pub kernel_start: u64,
    pub kernel_end: u64,
    pub virt_base: u64,
    pub cpuid_page: u64,
    pub secrets_page: u64,
    pub ghcb: u64,
}
