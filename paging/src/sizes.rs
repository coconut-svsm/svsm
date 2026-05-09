// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use verus_stub::*;

#[cfg(verus_only)]
#[path = "proofs/sizes.rs"]
mod sizes_spec_defs;
#[cfg(verus_only)]
pub use sizes_spec_defs::*;
#[cfg(verus_only)]
verus! {
    broadcast use sizes_spec_defs::group_types_proof;
}

verus! {

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SHIFT_2M: usize = 21;
pub const PAGE_SHIFT_1G: usize = 30;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_SIZE_2M: usize = 1 << PAGE_SHIFT_2M;
pub const PAGE_SIZE_1G: usize = 1 << PAGE_SHIFT_1G;

}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Regular,
    Huge,
}

impl From<PageSize> for usize {
    fn from(psize: PageSize) -> Self {
        match psize {
            PageSize::Regular => PAGE_SIZE,
            PageSize::Huge => PAGE_SIZE_2M,
        }
    }
}
