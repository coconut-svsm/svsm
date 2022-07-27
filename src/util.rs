// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::PAGE_SIZE;
use core::arch::asm;

pub fn align_up(addr : usize, align: usize) -> usize {
    addr + (align -1) & !(align - 1)
}

pub fn page_align(addr : usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

pub fn page_align_up(addr : usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub fn halt() {
    unsafe {
        asm!("hlt",
             options(att_syntax));
    }
}
