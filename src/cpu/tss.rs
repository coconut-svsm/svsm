// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use super::gdt::load_tss;

#[repr(C, packed)]
pub struct X86Tss {
    reserved1   : u32,
    stacks      : [u64; 3],
    reserved2   : u64,
    ist_stacks  : [u64; 7],
    reserved3   : u64,
    reserved4   : u16,
    io_bmp_base : u16,
}

pub const TSS_LIMIT : u64 = core::mem::size_of::<X86Tss>() as u64;

impl X86Tss {
    pub const fn new() -> Self {
        X86Tss {
            reserved1   : 0,
            stacks      : [0; 3],
            reserved2   : 0,
            ist_stacks  : [0; 7],
            reserved3   : 0,
            reserved4   : 0,
            io_bmp_base : (TSS_LIMIT + 1) as u16,
        }
    }
}

static mut BSP_TSS : X86Tss = X86Tss::new();

pub fn init_boot_tss() {
    unsafe {
        load_tss(&BSP_TSS);
    }
}
