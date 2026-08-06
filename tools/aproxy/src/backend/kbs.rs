// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::{Context, anyhow};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use kbs_types::*;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use sha2::{Digest, Sha384};

#[derive(Clone, Debug, Default)]
pub struct KbsProtocol {
    original_nonce: Option<String>,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    pub token: String,
}

impl AttestationProtocol for KbsProtocol {
    /// KBS servers usually want two components hashed into attestation evidence: the public
    /// components of the TEE key, and a nonce provided in the KBS challenge that is fetched
    /// from the server's /auth endpoint. These must be hased in order.
    ///
    /// Make this request to /auth, gather the nonce, and return this in the negotiation
    /// parameter for SVSM to hash these components in the attestation evidence.
    fn negotiation(
        &mut self,
        http: &mut HttpClient,
        request: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse> {
        if request.version != (0, 1, 0) {
            return Err(anyhow!("invalid request version"));
        }
        let req = Request {
            version: "0.4.0".to_string(),
            tee: request.tee,
            extra_params: Value::String("".to_string()), // unused.
        };

        // Fetch challenge containing a nonce from the KBS /auth endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/auth", http.url))
            .json(&req)
            .send()
            .context("unable to POST to KBS /auth endpoint")?;

        let text = http_resp
            .text()
            .context("unable to convert KBS /auth response to text")?;

        let challenge: Challenge =
            serde_json::from_str(&text).context("unable to convert KBS /auth response to JSON")?;

        self.original_nonce = Some(challenge.nonce.clone());

        let mut runtime_data = serde_json::Map::new();
        runtime_data.insert("additional-evidence".to_string(), json!(""));
        runtime_data.insert("nonce".to_string(), json!(challenge.nonce));

        let mut key_map = serde_json::Map::new();
        key_map.insert("alg".to_string(), json!("ECDH-ES+A256KW"));
        key_map.insert("crv".to_string(), json!("P-521"));
        key_map.insert("kty".to_string(), json!("EC"));
        key_map.insert(
            "x".to_string(),
            json!(BASE64_URL_SAFE_NO_PAD.encode(&request.key.x)),
        );
        key_map.insert(
            "y".to_string(),
            json!(BASE64_URL_SAFE_NO_PAD.encode(&request.key.y)),
        );

        runtime_data.insert("tee-pubkey".to_string(), json!(key_map));

        let json_bytes = serde_json::to_vec(&runtime_data)?;

        let mut hasher = Sha384::new();
        hasher.update(&json_bytes);
        let hash_result = hasher.finalize();

        Ok(NegotiationResponse {
            challenge: hash_result.to_vec(),
        })
    }

    /// With the serialized TEE evidence and key, complete the attestation. Serialize the evidence
    /// and send it to the /attest endpoint of the KBS server. Upon a successful attestation, fetch
    /// a secret (identified as "svsm_secret"). If able to successfully fetch the secret, return a
    /// successful AttestationResponse with the secret included.
    fn attestation(
        &mut self,
        http: &mut HttpClient,
        request: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse> {
        let evidence: KbsEvidence = (&request).try_into()?;

        // Create a KBS attestation object from the TEE evidence and key.
        let attestation = Attestation {
            init_data: None,
            runtime_data: RuntimeData {
                nonce: self
                    .original_nonce
                    .take()
                    .context("Original nonce is missing")?,
                tee_pubkey: request.key.into(),
            },
            tee_evidence: CompositeEvidence {
                primary_evidence: serde_json::to_value(&evidence)
                    .context("unable to serialize attestation evidence to JSON")?,
                additional_evidence: String::new(),
            },
        };

        // Attest TEE evidence at KBS /attest endpoint.
        let http_resp = http
            .cli
            .post(format!("{}/kbs/v0/attest", http.url))
            .json(&attestation)
            .send()
            .context("unable to POST to KBS /attest endpoint")?;

        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
                token: None,
            });
        }

        // Get the attestation token from the response.
        let token_resp: TokenResponse = serde_json::from_str(
            &http_resp
                .text()
                .context("unable to convert /attest response to text")?,
        )
        .context("unable to convert /attest response to JSON object")?;

        // Successful attestation. Fetch the secret (which should be stored at
        // /resource/default/sample/test in the KBS server instance.
        //
        // KBS offers a resource backend repository for testing, which includes the
        // default/sample/test file. Fetch the secret "hello, world" from this file to demonstrate
        // a secret fetch.
        //
        // TODO: Further modify this backend to support the KBS module's PKCS11 plugin.
        // With this, wrapped secrets can be POSTed to the PKCS11 plugin for unwrapping.
        let http_resp = http
            .cli
            .get(format!("{}/kbs/v0/resource/default/sample/test", http.url))
            .send()
            .context("unable to POST to KBS /attest endpoint")?;

        // Unsuccessful attempt at retrieving secret.
        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                success: false,
                secret: None,
                decryption: None,
                token: None,
            });
        }

        let text = http_resp
            .text()
            .context("unable to read KBS /resource response")?;

        let resp: Response = serde_json::from_str(&text)
            .context("unable to convert KBS /resource response to KBS Response object")?;

        let epk = unwrap_epk(&resp)?;
        let aad = resp
            .protected
            .generate_aad()
            .context("unable to generate AAD")?;

        Ok(AttestationResponse {
            success: true,
            secret: Some(resp.ciphertext),
            decryption: Some(AesGcmData {
                epk,
                wrapped_cek: resp.encrypted_key,
                aad,
                iv: resp.iv,
                tag: resp.tag,
            }),
            token: Some(AttestationToken::Jwt(token_resp.token)),
        })
    }
}

fn unwrap_epk(resp: &Response) -> anyhow::Result<EcP256PublicKey> {
    let epk = resp
        .protected
        .other_fields
        .get("epk")
        .context("epk not found")?;

    let _crv = epk
        .get("crv")
        .context("EC crv value not found")?
        .as_str()
        .context("unable to convert EC crv value to string")?;

    let x = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("x")
                .context("EC x value not found")?
                .as_str()
                .context("unable to convert EC x value to string")?,
        )
        .context("unable to decode EC x value from base64")?;

    let y = BASE64_URL_SAFE_NO_PAD
        .decode(
            epk.get("y")
                .context("EC y value not found")?
                .as_str()
                .context("unable to convert EC y value to string")?,
        )
        .context("unable to decode EC y value from base64")?;

    Ok(EcP256PublicKey { x, y })
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum KbsEvidence {
    Snp {
        #[serde(rename = "attestation_report")]
        snp_report: sev::firmware::guest::AttestationReport,
        #[serde(rename = "cert_chain")]
        certs_buf: Option<Vec<u8>>,
    },
}

impl TryFrom<&AttestationRequest> for KbsEvidence {
    type Error = anyhow::Error;
    fn try_from(data: &AttestationRequest) -> anyhow::Result<Self> {
        match data.tee {
            Tee::Snp => {
                let AttestationEvidence::Snp {
                    ref report,
                    certs_buf: _,
                } = data.evidence;

                use sev::parser::Decoder;
                let mut reader = std::io::Cursor::new(&report[..]);
                let report_struct =
                    sev::firmware::guest::AttestationReport::decode(&mut reader, ())
                        .context("unable to decode AttestationReport using sev::parser::Decoder")?;

                Ok(Self::Snp {
                    snp_report: report_struct,
                    certs_buf: None,
                })
            }
            _ => Err(anyhow!("invalid TEE")),
        }
    }
}
