// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

// The IGVM file builder requires zerocopy but not atomics, while the
// runtime environment requires atomics but not zerocopy.  Defining a single
// structure that can be compiled either way is possible but it breaks
// clippy, which forces all features to be on when performing checks - and
// therefore cannot observe the correct version of the structure in all
// environments.  Finding a way to fix this is possible but extremely
// impractical, so instead, the context stucture here is defined twice,
// once with atomics and once with `IntoBytes`.  Because the structure is so
// small, divergence is unlikely, but the two structures must be kept perfectly
// in sync.

use core::sync::atomic::AtomicU32;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

#[repr(C)]
#[derive(Debug, Default, FromBytes, IntoBytes, Immutable)]
pub struct TdpStartContextLayout {
    pub vp_index: u32,
    pub rip: u32,
    pub rsp: u32,
    pub ap_entry: u32,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes)]
pub struct TdpStartContext {
    pub vp_index: AtomicU32,
    pub rip: u32,
    pub rsp: u32,
    pub ap_entry: u32,
}
