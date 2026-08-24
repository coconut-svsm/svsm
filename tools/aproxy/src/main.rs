// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod attest;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use const_format::formatcp;
use libaproxy::ATTEST_DEFAULT_VSOCK_PORT;
use reqwest::blocking::ClientBuilder;
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
};
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
#[clap(group(clap::ArgGroup::new("transport").required(true)))]
struct Args {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Backend attestation protocol that the server implements.
    #[clap(long = "protocol")]
    backend: ArgsBackend,

    /// UNIX domain socket path to the SVSM serial port
    #[clap(long, group = "transport")]
    unix: Option<String>,

    /// vsock listening port where SVSM will connect [default: 1995]
    #[clap(long, group = "transport", num_args = 0..=1, default_missing_value = formatcp!("{}", ATTEST_DEFAULT_VSOCK_PORT))]
    vsock: Option<u32>,

    /// Force Unix domain socket removal before bind
    #[clap(long, short, conflicts_with = "vsock", default_value_t = false)]
    force: bool,

    /// Endpoint path for authentication [default: /kbs/v0/auth]
    #[clap(long = "auth-endpoint", default_value = "/kbs/v0/auth")]
    auth_endpoint: String,

    /// Endpoint path for attestation [default: /kbs/v0/attest]
    #[clap(long = "attest-endpoint", default_value = "/kbs/v0/attest")]
    attest_endpoint: String,

    /// Endpoint path for retrieving resources [default: /kbs/v0/resource/default/sample/test]
    #[clap(
        long = "resource-endpoint",
        default_value = "/kbs/v0/resource/default/sample/test"
    )]
    resource_endpoint: String,
}

/// Enum to represent possible backends in the CLI.
/// This must not have any attached data to its variants for `ValueEnum`
/// to work.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum ArgsBackend {
    /// Legacy or Mock KBS (raw public key & challenge, SHA-512)
    Kbs,
    /// Trustee KBS (JWS JSON, SHA-384)
    KbsTrustee,
}

fn accept_loop<S: Read + Write>(
    incoming: impl Iterator<Item = std::io::Result<S>>,
    url: &str,
    backend: ArgsBackend,
    auth_endpoint: String,
    attest_endpoint: String,
    resource_endpoint: String,
) -> anyhow::Result<()> {
    // Create a reqwest client with cookie store enabled to automatically handle session cookies
    let http_client = ClientBuilder::new()
        .cookie_store(true)
        .build()
        .context("failed to build reqwest HTTP client")?;

    for stream in incoming {
        let mut stream = stream.context("Failed to accept connection")?;
        attest::attest(
            &mut stream,
            &http_client,
            url,
            backend,
            auth_endpoint.clone(),
            attest_endpoint.clone(),
            resource_endpoint.clone(),
        )?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(port) = args.vsock {
        let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port))
            .context("bind and listen failed")?;
        accept_loop(
            listener.incoming(),
            &args.url,
            args.backend,
            args.auth_endpoint,
            args.attest_endpoint,
            args.resource_endpoint,
        )?;
    } else if let Some(unix) = args.unix {
        if args.force {
            let _ = fs::remove_file(&unix);
        }

        let listener = UnixListener::bind(unix).context("unable to bind to UNIX socket")?;
        accept_loop(
            listener.incoming(),
            &args.url,
            args.backend,
            args.auth_endpoint,
            args.attest_endpoint,
            args.resource_endpoint,
        )?;
    }

    Ok(())
}
