// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::error::SvsmError;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TdxSuccess {
    Success,
    PageAlreadyAccepted,
    Unknown(u64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TdxError {
    OperandInvalid,
    NoVeInfo,
    PageSizeMismatch,
    Unimplemented,
    Vmcall(TdVmcallError),
    Unknown(u64),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TdVmcallError {
    OperandInvalid,
    Retry,
    Unknown(u64),
}

impl From<TdxError> for SvsmError {
    fn from(err: TdxError) -> SvsmError {
        SvsmError::Tdx(err)
    }
}

pub fn tdx_result(err: u64) -> Result<TdxSuccess, TdxError> {
    let code = err >> 32;
    if code < 0x8000_0000 {
        match code {
            0 => Ok(TdxSuccess::Success),
            0x0000_0B0A => Ok(TdxSuccess::PageAlreadyAccepted),
            _ => Ok(TdxSuccess::Unknown(err)),
        }
    } else {
        match code {
            0xC000_0100 => Err(TdxError::OperandInvalid),
            0xC000_0704 => Err(TdxError::NoVeInfo),
            0xC000_0B0B => Err(TdxError::PageSizeMismatch),
            _ => Err(TdxError::Unknown(err)),
        }
    }
}

pub fn tdx_recoverable_error(err: u64) -> bool {
    // Bit 63: ERROR
    // Bit 62: NON_RECOVERABLE
    (err >> 62) == 2
}

pub fn tdvmcall_result(err: u64) -> Result<(), TdxError> {
    match err {
        0 => Ok(()),
        1 => Err(TdxError::Vmcall(TdVmcallError::Retry)),
        0x8000_0000_0000_0000 => Err(TdxError::Vmcall(TdVmcallError::OperandInvalid)),
        _ => Err(TdxError::Vmcall(TdVmcallError::Unknown(err))),
    }
}
