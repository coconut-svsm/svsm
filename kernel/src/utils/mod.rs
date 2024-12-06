// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod bitmap_allocator;
pub mod fw_meta;
pub mod immut_after_init;
pub mod memory_region;
pub mod util;

pub use memory_region::MemoryRegion;
pub use util::{
    align_down, align_up, halt, is_aligned, overlap, page_align_up, page_offset, zero_mem_region,
};

/// Determines whether an object supports `Sync`.  The function is written to
/// always return `true` because the compiler will prevent the function from
/// being called on any type that is not `Sync`.
pub fn is_sync<T: Sync>(_t: &T) -> bool {
    true
}
