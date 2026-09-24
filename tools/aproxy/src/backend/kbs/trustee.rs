// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat, Inc
//
// Author: Arun Menon <armenon@redhat.com>

use super::*;
use libaproxy::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default)]
pub struct TrusteeKbs;

impl KbsBackend for TrusteeKbs {
    fn hash_algo(&self) -> HashAlgo {
        HashAlgo::Sha384
    }

    fn payload_format(&self) -> PayloadFormat {
        PayloadFormat::JwsJson
    }

    fn get_primary_evidence(
        &self,
        evidence: &AttestationEvidence,
    ) -> anyhow::Result<serde_json::Value> {
        let AttestationEvidence::Snp {
            report,
            certs_buf: _,
        } = evidence;

        use sev::parser::Decoder;
        let mut reader = std::io::Cursor::new(&report[..]);
        let report_struct = sev::firmware::guest::AttestationReport::decode(&mut reader, ())
            .context("unable to decode AttestationReport using sev::parser::Decoder")?;

        let trustee_evidence = TrusteeEvidence::Snp {
            attestation_report: report_struct,
            cert_chain: None,
        };
        serde_json::to_value(&trustee_evidence)
            .context("unable to serialize Trustee attestation evidence to JSON")
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TrusteeEvidence {
    Snp {
        attestation_report: sev::firmware::guest::AttestationReport,
        cert_chain: Option<Vec<u8>>,
    },
}
