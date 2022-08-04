// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use core::alloc::{GlobalAlloc, Layout};
use crate::mm::alloc::ALLOCATOR;

pub unsafe fn alloc(layout : Layout) -> *mut u8 {
    ALLOCATOR.alloc(layout)
}

pub unsafe fn dealloc(ptr : *mut u8, layout : Layout) {
    ALLOCATOR.dealloc(ptr, layout);
}

pub unsafe fn alloc_zeroed(layout : Layout) -> *mut u8 {
    ALLOCATOR.alloc_zeroed(layout)
}

pub unsafe fn realloc(ptr : *mut u8, layout : Layout, new_size : usize) -> *mut u8 {
    ALLOCATOR.realloc(ptr, layout, new_size)
}

pub fn handle_alloc_error(layout : Layout) -> ! {
    panic!("Allocation of size {} failed", layout.size());
}
