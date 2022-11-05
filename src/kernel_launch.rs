// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

#[derive(Copy, Clone)]
pub struct KernelLaunchInfo {
    pub kernel_start: u64,
    pub kernel_end: u64,
    pub virt_base: u64,
    pub cpuid_page: u64,
    pub secrets_page: u64,
    pub ghcb: u64,
}
