// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// The initial payload sent from SVSM to the attestation proxy. The version indicates the version
/// of the SVSM attestation protocol to use.
#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationRequest {
    pub version: String,
    pub tee: kbs_types::Tee,
}

/// A parameter that must be hashed into the negotiation hash.
#[derive(Serialize, Deserialize, Debug)]
pub enum NegotiationParam {
    /// Hash the EC public key's `Elliptic-Curve-Point-to-Octet-String` encoding.
    EcPublicKeyBytes,
    /// A base64-encoded byte array. This could represent a nonce or any other data the
    /// attestation server would like to embed in TEE evidence.
    Base64StdBytes(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationResponse {
    /// Parameters to be hashed in the specific order defined by the array
    pub params: Vec<NegotiationParam>,
}
