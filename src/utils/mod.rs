// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod bitmap_allocator;
pub mod immut_after_init;
pub mod util;

pub use util::{align_down, align_up, halt, overlap, page_align_up, page_offset, zero_mem_region};
