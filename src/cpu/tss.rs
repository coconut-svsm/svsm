// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;

// IST offsets
pub const _IST_INVALID: usize = 0;
pub const IST_DF: usize = 1;

#[repr(C, packed)]
pub struct X86Tss {
    reserved1: u32,
    pub stacks: [VirtAddr; 3],
    pub ist_stacks: [VirtAddr; 8],
    reserved2: u64,
    reserved3: u16,
    io_bmp_base: u16,
}

pub const TSS_LIMIT: u64 = core::mem::size_of::<X86Tss>() as u64;

impl X86Tss {
    pub const fn new() -> Self {
        X86Tss {
            reserved1: 0,
            stacks: [VirtAddr::null(); 3],
            ist_stacks: [VirtAddr::null(); 8],
            reserved2: 0,
            reserved3: 0,
            io_bmp_base: (TSS_LIMIT + 1) as u16,
        }
    }
}
