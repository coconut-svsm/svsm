// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

/// Defines the underlying platform type on which the SVSM will run.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub enum SvsmPlatformType {
    Native = 0,
    Snp = 1,
}
