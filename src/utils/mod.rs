// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub mod util;
pub mod immut_after_init;

pub use util::{align_up, ffs, halt, page_offset, page_align, page_align_up, is_aligned, crosses_page, zero_mem_region, overlap};
