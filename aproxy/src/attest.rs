// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use anyhow::Context;
use libaproxy::*;
use std::{io::Read, os::unix::net::UnixStream};

/// Attest an SVSM client session.
pub fn attest(stream: &mut UnixStream) -> anyhow::Result<()> {
    negotiation(stream)?;

    Ok(())
}

/// Negotiation phase of SVSM attestation. SVSM will send a negotiation request indicating the
/// version that it would like to use. The proxy will then reach out to the respective attestation
/// server and gather all data required (i.e. a nonce) that should be hashed into the attestation
/// evidence. The proxy will also reply with the type of hash algorithm to use for the negotiation
/// parameters.
fn negotiation(stream: &mut UnixStream) -> anyhow::Result<()> {
    // Read the negotiation parameters from SVSM.
    let _request: NegotiationRequest = {
        let payload = proxy_read(stream)?;

        serde_json::from_slice(&payload)
            .context("unable to deserialize negotiation request from JSON")?
    };

    todo!();
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
