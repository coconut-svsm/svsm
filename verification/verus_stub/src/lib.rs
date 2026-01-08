// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

#![no_std]

#[cfg(feature = "disable")]
pub use verus_builtin_macros::*;

#[cfg(feature = "disable")]
pub use vstd::prelude::*;

#[cfg(not(feature = "disable"))]
pub use verus_macro_stub::*;
