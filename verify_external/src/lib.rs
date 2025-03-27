// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Goal: This crate provides specifications for external, unverified libraries.
// These specifications are placeholders, and the number of verification targets
// should always remain zero since these libraries are not formally verified.
// Why: While vstd defines some specifications for std/core, these are
// incomplete. SVSM may also rely on other unverified crates, which necessitates
// these specifications.

#![no_std]
#![allow(unused_braces)]
#![allow(unexpected_cfgs)]

// Add spec for convert traits
pub mod convert;

use builtin_macros::*;

verus! {
#[cfg_attr(verus_keep_ghost, verifier::broadcast_use_by_default_when_this_crate_is_imported)]
pub broadcast group external_axiom {
}
}
