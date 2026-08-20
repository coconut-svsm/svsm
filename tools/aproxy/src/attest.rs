// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use crate::ArgsBackend;
use anyhow::{Context, anyhow};
use libaproxy::*;
use reqwest::blocking::Client;
use serde::Serialize;
use std::io::{Read, Write};

/// Attest an SVSM client session.
pub fn attest(
    stream: &mut (impl Read + Write),
    http_client: &Client,
    backend_url: &str,
    backend: ArgsBackend,
    auth_endpoint: String,
    attest_endpoint: String,
    resource_endpoint: String,
) -> anyhow::Result<()> {
    let config_req: ConfigRequest = {
        let payload = proxy_read(stream)?;
        serde_json::from_slice(&payload)
            .context("unable to deserialize config request from JSON")?
    };

    if config_req.version != (0, 1, 0) {
        return Err(anyhow!("unsupported SVSM attestation protocol version"));
    }

    let (hash_algo, payload_format) = match backend {
        ArgsBackend::Kbs => (HashAlgo::Sha512, PayloadFormat::RawBinary),
        ArgsBackend::KbsTrustee => (HashAlgo::Sha384, PayloadFormat::JwsJson),
    };

    let config_resp = ConfigResponse {
        hash_algo,
        payload_format,
        auth_endpoint,
        attest_endpoint,
        resource_endpoint,
    };

    proxy_write(stream, config_resp)?;

    loop {
        let payload = match proxy_read(stream) {
            Ok(payload) => payload,
            Err(_) => {
                // EOF is expected when SVSM disconnects after completing attestation
                break;
            }
        };

        let req: ProxyRequest = match serde_json::from_slice(&payload) {
            Ok(req) => req,
            Err(_) => break,
        };

        let url_req = format!("{}{}", backend_url, req.endpoint);
        let http_req = match req.method {
            HttpMethod::GET => http_client.get(&url_req).json(&req.body),
            HttpMethod::POST => http_client.post(&url_req).json(&req.body),
        };

        let http_resp = match http_req.send() {
            Ok(resp) => resp,
            Err(e) => {
                let resp = ProxyResponse {
                    status: 500,
                    body: e.to_string(),
                };
                proxy_write(stream, resp)?;
                continue;
            }
        };

        let resp = ProxyResponse {
            status: http_resp.status().as_u16(),
            body: http_resp.text().unwrap_or_default(),
        };

        proxy_write(stream, resp)?;
    }

    Ok(())
}

fn proxy_read(stream: &mut impl Read) -> anyhow::Result<Vec<u8>> {
    let len = {
        let mut bytes = [0u8; 8];

        stream
            .read_exact(&mut bytes)
            .context("unable to read request buffer length from socket")?;

        usize::from_ne_bytes(bytes)
    };

    let mut bytes = vec![0u8; len];

    stream
        .read_exact(&mut bytes)
        .context("unable to read request buffer from socket")?;

    Ok(bytes)
}

fn proxy_write(stream: &mut impl Write, buf: impl Serialize) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&buf).context("unable to convert buffer to JSON bytes")?;
    let len = bytes.len().to_ne_bytes();

    stream
        .write_all(&len)
        .context("unable to write buffer length to socket")?;
    stream
        .write_all(&bytes)
        .context("unable to write buffer to socket")?;

    Ok(())
}
