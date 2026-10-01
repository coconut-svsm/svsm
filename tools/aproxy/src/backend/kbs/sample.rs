// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat, Inc
//
// Author: Arun Menon <armenon@redhat.com>

use super::*;
use base64::{Engine, prelude::BASE64_STANDARD};
use libaproxy::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default)]
pub struct SampleKbs;

impl KbsBackend for SampleKbs {
    fn hash_algo(&self) -> HashAlgo {
        HashAlgo::Sha512
    }

    fn payload_format(&self) -> PayloadFormat {
        PayloadFormat::RawBinary
    }

    fn get_primary_evidence(
        &self,
        evidence: &AttestationEvidence,
    ) -> anyhow::Result<serde_json::Value> {
        let evidence: SampleEvidence = evidence.try_into()?;
        serde_json::to_value(&evidence).context("unable to serialize attestation evidence to JSON")
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SampleEvidence {
    Snp {
        #[serde(rename = "snp-report")]
        snp_report: String,
        #[serde(rename = "certs-buf")]
        certs_buf: Option<String>,
    },
}

impl TryFrom<&AttestationEvidence> for SampleEvidence {
    type Error = anyhow::Error;

    #[allow(irrefutable_let_patterns)]
    fn try_from(evidence: &AttestationEvidence) -> std::result::Result<Self, Self::Error> {
        let AttestationEvidence::Snp { report, certs_buf } = evidence else {
            anyhow::bail!("invalid SEV-SNP evidence")
        };

        Ok(Self::Snp {
            snp_report: BASE64_STANDARD.encode(report),
            certs_buf: certs_buf.clone().map(|certs| BASE64_STANDARD.encode(certs)),
        })
    }
}
