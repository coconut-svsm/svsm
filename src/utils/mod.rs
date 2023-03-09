// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub mod immut_after_init;
pub mod util;

pub use util::{
    align_up, crosses_page, ffs, halt, is_aligned, overlap, page_align, page_align_up, page_offset,
    zero_mem_region,
};
