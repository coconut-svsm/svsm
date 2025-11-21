// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>

#![no_std]
#![allow(unused_braces)]
#![allow(unexpected_cfgs)]
#![allow(missing_debug_implementations)]
use verus_builtin_macros::*;

pub mod bits;
#[cfg(verus_keep_ghost)]
pub mod frac_perm;
#[cfg(verus_keep_ghost)]
pub mod frac_ptr;
#[cfg(verus_keep_ghost)]
pub mod nonlinear;
#[cfg(verus_keep_ghost)]
pub mod set;
#[cfg(verus_keep_ghost)]
pub mod sum;

verus! {

global size_of usize == 8;

#[cfg_attr(verus_keep_ghost, verifier::broadcast_use_by_default_when_this_crate_is_imported)]
pub broadcast group group_axioms {
    set::lemma_set_usize_finite,
}

} // verus!
