// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
pub enum SvsmResultCode {
    SUCCESS,
    INCOMPLETE,
    UNSUPPORTED_PROTOCOL,
    UNSUPPORTED_CALL,
    INVALID_ADDRESS,
    INVALID_FORMAT,
    INVALID_PARAMETER,
    INVALID_REQUEST,
    BUSY,
    PROTOCOL_BASE(u64),
}

impl From<SvsmResultCode> for u64 {
    fn from(res: SvsmResultCode) -> u64 {
        match res {
            SvsmResultCode::SUCCESS => 0x0000_0000,
            SvsmResultCode::INCOMPLETE => 0x8000_0000,
            SvsmResultCode::UNSUPPORTED_PROTOCOL => 0x8000_0001,
            SvsmResultCode::UNSUPPORTED_CALL => 0x8000_0002,
            SvsmResultCode::INVALID_ADDRESS => 0x8000_0003,
            SvsmResultCode::INVALID_FORMAT => 0x8000_0004,
            SvsmResultCode::INVALID_PARAMETER => 0x8000_0005,
            SvsmResultCode::INVALID_REQUEST => 0x8000_0006,
            SvsmResultCode::BUSY => 0x8000_0007,
            SvsmResultCode::PROTOCOL_BASE(code) => 0x8000_1000 + code,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SvsmReqError {
    RequestError(SvsmResultCode),
    FatalError(SvsmError),
}

macro_rules! impl_req_err {
    ($name:ident, $v:ident) => {
        pub fn $name() -> Self {
            Self::RequestError(SvsmResultCode::$v)
        }
    };
}

#[allow(dead_code)]
impl SvsmReqError {
    impl_req_err!(incomplete, INCOMPLETE);
    impl_req_err!(unsupported_protocol, UNSUPPORTED_PROTOCOL);
    impl_req_err!(unsupported_call, UNSUPPORTED_CALL);
    impl_req_err!(invalid_address, INVALID_ADDRESS);
    impl_req_err!(invalid_format, INVALID_FORMAT);
    impl_req_err!(invalid_parameter, INVALID_PARAMETER);
    impl_req_err!(invalid_request, INVALID_REQUEST);
    impl_req_err!(busy, BUSY);
    pub fn protocol(code: u64) -> Self {
        Self::RequestError(SvsmResultCode::PROTOCOL_BASE(code))
    }
}

impl From<SvsmError> for SvsmReqError {
    fn from(err: SvsmError) -> Self {
        match err {
            SvsmError::Mem => Self::FatalError(err),
            // SEV-SNP errors obtained from PVALIDATE or RMPADJUST are returned
            // to the guest as protocol-specific errors.
            SvsmError::SevSnp(e) => Self::protocol(e.ret()),
            SvsmError::InvalidAddress => Self::invalid_address(),
            // Use a fatal error for now
            _ => Self::FatalError(err),
        }
    }
}
