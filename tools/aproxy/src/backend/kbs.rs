// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::{Context, bail};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use kbs_types::*;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default)]
pub struct KbsProtocol;

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

        // Challenge nonce is a base64-encoded byte vector. Inform SVSM of this so it could
        // decode the bytes and hash them into the TEE evidence.
        let params = vec![
            NegotiationParam::EcPublicKeyBytes,
            NegotiationParam::Challenge,
        ];

        let resp = NegotiationResponse {
            challenge: BASE64_STANDARD
                .decode(challenge.nonce)
                .context("unable to decode challenge nonce from base64")?,
            params,
        };

        Ok(resp)
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
                nonce: BASE64_STANDARD.encode(request.challenge),
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
        #[serde(rename = "snp-report")]
        snp_report: String,
        #[serde(rename = "certs-buf")]
        certs_buf: Option<String>,
    },
}

impl TryFrom<&AttestationRequest> for KbsEvidence {
    type Error = anyhow::Error;

    // At the moment, only SEV-SNP evidence is allowed. However, preserve the following match
    // statement to describe how other TEE architectures would serialize AttestationEvidence.
    #[allow(irrefutable_let_patterns)]
    fn try_from(data: &AttestationRequest) -> anyhow::Result<Self> {
        match data.tee {
            Tee::Snp => {
                let AttestationEvidence::Snp {
                    ref report,
                    ref certs_buf,
                } = data.evidence
                else {
                    bail!("invalid SEV-SNP evidence")
                };

                Ok(Self::Snp {
                    snp_report: BASE64_STANDARD.encode(report),
                    certs_buf: certs_buf.clone().map(|certs| BASE64_STANDARD.encode(certs)),
                })
            }
            _ => Err(anyhow!("invalid TEE")),
        }
    }
}
