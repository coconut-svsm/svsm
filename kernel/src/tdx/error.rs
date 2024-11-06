// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::error::SvsmError;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TdxError {
    Unknown(u64),
    Unimplemented,
    PageAlreadyAccepted,
    PageSizeMismatch,
}

impl From<TdxError> for SvsmError {
    fn from(err: TdxError) -> SvsmError {
        SvsmError::Tdx(err)
    }
}

pub fn tdx_result(err: u64) -> Result<u64, TdxError> {
    let code = err >> 32;
    if code < 0x8000_0000 {
        return Ok(code);
    }
    match code {
        0xC000_0B0A => Err(TdxError::PageAlreadyAccepted),
        0xC000_0B0B => Err(TdxError::PageSizeMismatch),
        _ => Err(TdxError::Unknown(err)),
    }
}
