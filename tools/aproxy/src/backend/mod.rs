// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod kbs;

use crate::ArgsBackend;
use anyhow::Context;
use kbs::KbsProtocol;
use libaproxy::*;
use reqwest::{blocking::Client, cookie::Jar};
use std::mem;
use std::sync::Arc;

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
        let mut protocol = mem::replace(&mut self.protocol, Protocol::Kbs(KbsProtocol::default()));
        let result = match &mut protocol {
            Protocol::Kbs(kbs) => kbs.negotiation(self, req),
        };
        self.protocol = protocol;
        result
    }

    pub fn attestation(&mut self, req: AttestationRequest) -> anyhow::Result<AttestationResponse> {
        let mut protocol = mem::replace(&mut self.protocol, Protocol::Kbs(KbsProtocol::default()));
        let result = match &mut protocol {
            Protocol::Kbs(kbs) => kbs.attestation(self, req),
        };
        self.protocol = protocol;
        result
    }
}

/// Attestation Protocol identifier.
#[derive(Clone, Debug)]
pub enum Protocol {
    Kbs(KbsProtocol),
}

impl From<ArgsBackend> for Protocol {
    fn from(value: ArgsBackend) -> Self {
        match value {
            ArgsBackend::Kbs => Self::Kbs(KbsProtocol::default()),
        }
    }
}

/// Trait to implement the negotiation and attestation phases across different attestation
/// protocols.
pub trait AttestationProtocol {
    fn fetch_secret(
        &self,
        http: &mut HttpClient,
        req: &SecretRequest,
        token: &str,
    ) -> anyhow::Result<reqwest::blocking::Response>;
    fn negotiation(
        &mut self,
        client: &mut HttpClient,
        req: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse>;
    fn attestation(
        &mut self,
        client: &mut HttpClient,
        req: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse>;
}
