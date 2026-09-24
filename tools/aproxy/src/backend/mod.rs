// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod kbs;

use crate::ArgsBackend;
use anyhow::Context;
use kbs::{KbsProtocol, SampleKbs, TrusteeKbs};
use libaproxy::*;
use reqwest::{blocking::Client, cookie::Jar};
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
        let mut protocol = self.protocol;
        match &mut protocol {
            Protocol::SampleKbs(kbs) => kbs.negotiation(self, req),
            Protocol::TrusteeKbs(kbs) => kbs.negotiation(self, req),
        }
    }

    pub fn attestation(&mut self, req: AttestationRequest) -> anyhow::Result<AttestationResponse> {
        let mut protocol = self.protocol;
        match &mut protocol {
            Protocol::SampleKbs(kbs) => kbs.attestation(self, req),
            Protocol::TrusteeKbs(kbs) => kbs.attestation(self, req),
        }
    }
}

/// Attestation Protocol identifier.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    SampleKbs(KbsProtocol<SampleKbs>),
    TrusteeKbs(KbsProtocol<TrusteeKbs>),
}

impl From<ArgsBackend> for Protocol {
    fn from(value: ArgsBackend) -> Self {
        match value {
            ArgsBackend::SampleKbs => Self::SampleKbs(KbsProtocol::new(SampleKbs)),
            ArgsBackend::TrusteeKbs => Self::TrusteeKbs(KbsProtocol::new(TrusteeKbs)),
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
    fn attestation(
        &mut self,
        client: &mut HttpClient,
        req: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse>;
}
