// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

#![no_std]

mod attestation;
mod negotiation;

pub use attestation::*;
pub use negotiation::*;

#[derive(Debug)]
pub enum Error {
    InvalidKeyType,
    KeyParamDecode(base64::DecodeError),
    InvalidParams,
}
