// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod immut_after_init;
pub mod util;

pub use util::{
    align_up, crosses_page, ffs, halt, is_aligned, overlap, page_align, page_align_up, page_offset,
    rdrand64, zero_mem_region,
};
