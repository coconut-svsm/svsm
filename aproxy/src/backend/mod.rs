// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

pub mod kbs;

use anyhow::anyhow;
use lazy_static::lazy_static;
use libaproxy::*;
use reqwest::blocking::Client;
use std::{str::FromStr, sync::Mutex};

lazy_static! {
    pub static ref BACKEND: Mutex<Option<ProtocolDispatcher>> = Mutex::new(None);
}

/// HTTP client and protocol identifier.
#[derive(Clone, Debug)]
pub struct ProtocolDispatcher {
    pub url: String,
    pub negotiation: fn(&Client, &str, NegotiationRequest) -> anyhow::Result<NegotiationResponse>,
    pub attestation: fn(&Client, &str, AttestationRequest) -> anyhow::Result<AttestationResponse>,
}

impl ProtocolDispatcher {
    pub fn negotiation(
        &self,
        cli: &Client,
        n: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse> {
        (self.negotiation)(cli, &self.url, n)
    }

    pub fn attestation(
        &self,
        cli: &Client,
        a: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse> {
        (self.attestation)(cli, &self.url, a)
    }
}

/// Attestation Protocol identifier.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Kbs,
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.to_lowercase()[..] {
            "kbs" => Ok(Self::Kbs),
            _ => Err(anyhow!("invalid backend attestation protocol selected")),
        }
    }
}

/// Trait to implement the negotiation and attestation phases across different attestation
/// protocols.
pub trait AttestationProtocol {
    fn negotiation(
        client: &Client,
        url: &str,
        req: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse>;
    fn attestation(
        client: &Client,
        url: &str,
        req: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse>;
}
