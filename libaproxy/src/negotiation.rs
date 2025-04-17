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

/// The hash algorithm that SVSM must use to hash all negotiation parameters. This hash should
/// eventually be part of a signed attestation report (for example, through SEV-SNP's REPORT_DATA
/// mechanism).
#[derive(Serialize, Deserialize, Debug)]
pub enum NegotiationHash {
    SHA384,
    SHA512,
}

/// The type of asymmetric key that must be generated by SVSM to decrypt secrets from the
/// attestation server.
#[derive(Serialize, Deserialize, Debug)]
pub enum NegotiationKey {
    Ecdh384Sha256Aes128,
}

/// A parameter that must be hashed into the negotiation hash.
#[derive(Serialize, Deserialize, Debug)]
pub enum NegotiationParam {
    /// Hash the EC public key's `Elliptic-Curve-Point-to-Octet-String` encoding.
    EcPublicKeySec1Bytes,
    /// A base64-encoded byte array. This could represent a nonce or any other data the
    /// attestation server would like to embed in TEE evidence.
    Base64StdBytes(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NegotiationResponse {
    /// The hash algorithm for negotiation parameters.
    pub hash: NegotiationHash,
    /// Type of asymmetric key to generate.
    pub key_type: NegotiationKey,
    /// Parameters to be hashed in the specific order defined by the array
    pub params: Vec<NegotiationParam>,
}
