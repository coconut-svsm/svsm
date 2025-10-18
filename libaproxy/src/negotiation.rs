// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;
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

/// A parameter that must be hashed into the negotiation hash.
#[derive(Serialize, Deserialize, Debug)]
pub enum NegotiationParam {
    /// Hash the challenge returned from attestation server.
    Challenge,
    /// Hash the EC public key's `Elliptic-Curve-Point-to-Octet-String` encoding.
    EcPublicKeyBytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationResponse {
    /// Challenge returned from the attestation server to verify freshness of attestation evidence.
    pub challenge: Vec<u8>,
    /// Parameters to be hashed in the specific order defined by the array
    pub params: Vec<NegotiationParam>,
}
