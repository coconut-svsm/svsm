// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod kbs;

use anyhow::{anyhow, Context};
use kbs::KbsProtocol;
use libaproxy::*;
use reqwest::{blocking::Client, cookie::Jar};
use std::{str::FromStr, sync::Arc};

/// HTTP client and protocol identifier.
#[derive(Clone, Debug)]
pub struct HttpClient {
    pub cli: Client,
    pub url: String,
    protocol: Protocol,
}

impl HttpClient {
    pub fn new(url: String, protocol: Protocol) -> anyhow::Result<Self> {
        let cli = Client::builder()
            .cookie_provider(Arc::new(Jar::default()))
            .build()
            .context("unable to build HTTP client to interact with attestation server")?;

        Ok(Self { cli, url, protocol })
    }

    pub fn negotiation(&mut self, req: NegotiationRequest) -> anyhow::Result<NegotiationResponse> {
        // Depending on the underlying protocol of the attestation server, gather negotiation
        // parameters accordingly.
        match self.protocol {
            Protocol::Kbs(mut kbs) => kbs.negotiation(self, req),
        }
    }
}

/// Attestation Protocol identifier.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Kbs(KbsProtocol),
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.to_lowercase()[..] {
            "kbs" => Ok(Self::Kbs(KbsProtocol)),
            _ => Err(anyhow!("invalid backend attestation protocol selected")),
        }
    }
}

/// Trait to implement the negotiation and attestation phases across different attestation
/// protocols.
pub trait AttestationProtocol {
    fn negotiation(
        &mut self,
        client: &mut HttpClient,
        req: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse>;
}
