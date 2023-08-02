// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::types::PAGE_SIZE;
use core::arch::asm;

pub fn align_up(addr: usize, align: usize) -> usize {
    (addr + (align - 1)) & !(align - 1)
}

pub fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

pub fn halt() {
    unsafe {
        asm!("hlt", options(att_syntax));
    }
}

pub fn page_align_up(x: usize) -> usize {
    (x + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub fn page_offset(x: usize) -> usize {
    x & (PAGE_SIZE - 1)
}

pub fn overlap<T>(x1: T, x2: T, y1: T, y2: T) -> bool
where
    T: core::cmp::PartialOrd,
{
    x1 <= y2 && y1 <= x2
}

pub fn zero_mem_region(start: VirtAddr, end: VirtAddr) {
    let size = end - start;
    if start.is_null() {
        panic!("Attempted to zero out a NULL pointer");
    }

    // Zero region
    unsafe { start.as_mut_ptr::<u8>().write_bytes(0, size) }
}

/// Obtain bit for a given position
#[macro_export]
macro_rules! BIT {
    ($x: expr) => {
        (1 << ($x))
    };
}
