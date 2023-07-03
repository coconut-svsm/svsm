// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use core::arch::asm;

pub fn rdtsc() -> u64 {
    let eax: u32;
    let edx: u32;

    unsafe {
        asm!("rdtsc",
             out("eax") eax,
             out("edx") edx,
             options(att_syntax));
    }
    (eax as u64) | (edx as u64) << 32
}
