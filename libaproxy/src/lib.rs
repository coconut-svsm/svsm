// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

#![no_std]

extern crate alloc;

mod attestation;
mod negotiation;

pub use attestation::*;
pub use negotiation::*;

use alloc::{string::String, vec::Vec};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde::Deserialize;

#[derive(Debug)]
pub enum Error {
    InvalidKeyType,
    KeyParamDecode(base64::DecodeError),
    InvalidParams,
}

fn serialize_base64<S>(sub: &Vec<u8>, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = BASE64_STANDARD.encode(sub);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> core::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;

    Ok(decoded)
}

fn serialize_base64_option<S>(
    sub: &Option<Vec<u8>>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match sub {
        Some(value) => {
            let encoded = BASE64_STANDARD.encode(value);
            serializer.serialize_str(&encoded)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_base64_option<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;

    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;

    Ok(Some(decoded))
}
