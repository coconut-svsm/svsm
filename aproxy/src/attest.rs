// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use crate::backend;
use anyhow::Context;
use libaproxy::*;
use serde::Serialize;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};

/// Attest an SVSM client session.
pub fn attest(stream: &mut UnixStream, http: &mut backend::HttpClient) -> anyhow::Result<()> {
    negotiation(stream, http)?;
    attestation(stream, http)?;

    // FIXME: When this function returns, the thread is terminated and the socket connection is
    // closed. However, there is currently a bug in QEMU in which the attestation driver is unable
    // to read the response from the proxy after the connection is closed.
    //
    // For now, effectively block the proxy process by waiting on a read from the driver that will
    // never occur. Instead, the read will terminate once the driver closes the socket connection.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    Ok(())
}

/// Negotiation phase of SVSM attestation. SVSM will send a negotiation request indicating the
/// version that it would like to use. The proxy will then reach out to the respective attestation
/// server and gather all data required (i.e. a nonce) that should be hashed into the attestation
/// evidence. The proxy will also reply with the type of hash algorithm to use for the negotiation
/// parameters.
fn negotiation(stream: &mut UnixStream, http: &mut backend::HttpClient) -> anyhow::Result<()> {
    // Read the negotiation parameters from SVSM.
    let request: NegotiationRequest = {
        let payload = proxy_read(stream)?;

        serde_json::from_slice(&payload)
            .context("unable to deserialize negotiation request from JSON")?
    };

    // Gather negotiation parameters from the attestation server.
    let response: NegotiationResponse = http.negotiation(request)?;

    // Write the response from the attestation server to SVSM.
    proxy_write(stream, response)?;

    Ok(())
}

/// Attestation phase of SVSM attestation. SVSM will send an attestation request containing the TEE
/// evidence. Proxy will respond with an attestation response containing the status
/// (success/failure) and an optional secret upon successful attestation.
fn attestation(stream: &mut UnixStream, http: &backend::HttpClient) -> anyhow::Result<()> {
    let request: AttestationRequest = {
        let payload = proxy_read(stream)?;
        serde_json::from_slice(&payload)
            .context("unable to deserialize attestation request from JSON")?
    };

    // Attest the TEE evidence with the server.
    let response: AttestationResponse = http.attestation(request)?;

    // Write the response from the attestation server to SVSM.
    proxy_write(stream, response)?;

    Ok(())
}

/// Read bytes from the UNIX socket connected to SVSM. With each write, SVSM first writes an 8-byte
/// header indicating the length of the buffer. Once the length is read, the buffer can be read.
fn proxy_read(stream: &mut UnixStream) -> anyhow::Result<Vec<u8>> {
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

/// Write bytes to the UNIX socket connected to SVSM. With each write, an 8-byte header indicating
/// the length of the buffer is written. Once the length is written, the buffer is written.
fn proxy_write(stream: &mut UnixStream, buf: impl Serialize) -> anyhow::Result<()> {
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
