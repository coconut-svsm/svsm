// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use super::*;
use alloc::string::String;
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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationParam {
    /// Hash the challenge returned from attestation server.
    Challenge,
    /// Hash the EC public key's `Elliptic-Curve-Point-to-Octet-String` encoding.
    EcPublicKeyBytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationResponse {
    /// Challenge returned from the attestation server to verify freshness of attestation evidence.
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub challenge: Vec<u8>,
    /// Parameters to be hashed in the specific order defined by the array
    pub params: Vec<NegotiationParam>,
}

pub use kbs_types::HashAlgorithm as HashAlgo;

/// The payload serialization format SVSM should use to organize public key components and nonces.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// Raw sequential binary representation of public key coordinates and challenge.
    RawBinary,
    /// JWS-compliant JSON formatted representation of runtime_data.
    JwsJson,
}

/// Request sent from SVSM to aproxy to retrieve the server-configured attestation parameters.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigRequest {
    /// Version of the SVSM attestation protocol, represented as semver (MAJOR.MINOR.PATCH).
    pub version: (u32, u32, u32),
    pub tee: kbs_types::Tee,
}

/// Response containing the required attestation parameters configured by the host administrator.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigResponse {
    pub hash_algo: HashAlgo,
    pub payload_format: PayloadFormat,
    pub auth_endpoint: String,
    pub attest_endpoint: String,
    pub resource_endpoint: String,
}

/// Supported HTTP methods for proxy forwarding.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
pub enum HttpMethod {
    GET,
    POST,
}

/// A generic HTTP forwarding request sent from SVSM to aproxy.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ProxyRequest {
    pub endpoint: String,
    pub method: HttpMethod,
    pub body: serde_json::Value,
}

/// A generic HTTP response sent back from aproxy to SVSM.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ProxyResponse {
    pub status: u16,
    pub body: String,
}

/// Challenge response format returned by the legacy mock server containing dynamic parameters.
#[derive(Serialize, Deserialize, Debug)]
pub struct LegacyChallenge {
    pub nonce: String,
    pub params: Vec<NegotiationParam>,
}
