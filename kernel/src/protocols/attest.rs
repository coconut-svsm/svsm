// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Coconut-SVSM Authors
//

//! Attest protocol implementation

use crate::protocols::{errors::SvsmReqError, RequestParams};

pub fn attest_protocol_request(
    request: u32,
    _params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}
