// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

// IST offsets
pub const _IST_INVALID : usize = 0;
pub const IST_DF : usize = 1;

#[repr(C, packed)]
pub struct X86Tss {
        reserved1   : u32,
    pub stacks      : [usize; 3],
    pub ist_stacks  : [usize; 8],
        reserved2   : u64,
        reserved3   : u16,
        io_bmp_base : u16,
}

pub const TSS_LIMIT : u64 = core::mem::size_of::<X86Tss>() as u64;

impl X86Tss {
    pub const fn new() -> Self {
        X86Tss {
            reserved1   : 0,
            stacks      : [0; 3],
            ist_stacks  : [0; 8],
            reserved2   : 0,
            reserved3   : 0,
            io_bmp_base : (TSS_LIMIT + 1) as u16,
        }
    }
}
