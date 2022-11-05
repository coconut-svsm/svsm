// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use super::cpuid::cpuid_table;

const X86_FEATURE_NX: u32 = 20;
const X86_FEATURE_PGE: u32 = 13;

pub fn cpu_has_nx() -> bool {
    let ret = cpuid_table(0x80000001);

    match ret {
        None => false,
        Some(c) => (c.edx >> X86_FEATURE_NX) & 1 == 1,
    }
}

pub fn cpu_has_pge() -> bool {
    let ret = cpuid_table(0x00000001);

    match ret {
        None => false,
        Some(c) => (c.edx >> X86_FEATURE_PGE) & 1 == 1,
    }
}
