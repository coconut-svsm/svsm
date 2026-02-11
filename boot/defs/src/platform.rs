// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

/// Defines the underlying platform type on which the SVSM will run.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum SvsmPlatformType {
    Native = 0,
    Snp = 1,
    Tdp = 2,
}

impl From<u32> for SvsmPlatformType {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Snp,
            2 => Self::Tdp,
            _ => Self::Native,
        }
    }
}

impl From<SvsmPlatformType> for u32 {
    fn from(p: SvsmPlatformType) -> u32 {
        p as u32
    }
}
