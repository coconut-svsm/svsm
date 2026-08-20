// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use super::*;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The initial payload sent from SVSM to the attestation proxy. The version indicates the version
/// of the SVSM attestation protocol to use.
#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationRequest {
    /// Version of the attestation protocol, represented as semver (MAJOR.MINOR.PATCH).
    pub version: (u32, u32, u32),
    pub tee: kbs_types::Tee,
}

/// The cryptographic hashing algorithm SVSM should use to digest the formatted payload.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}

/// The payload serialization format SVSM should use to organize public key components and nonces.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// Raw sequential binary representation of public key coordinates and challenge.
    RawBinary,
    /// JWS-compliant JSON formatted representation of runtime_data.
    JwsJson,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationResponse {
    /// Challenge returned from the attestation server to verify freshness of attestation evidence.
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub challenge: Vec<u8>,
    /// The hashing algorithm to use.
    pub hash_algo: HashAlgo,
    /// The payload formatting to use.
    pub payload_format: PayloadFormat,
}
