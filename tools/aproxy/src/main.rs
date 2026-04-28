// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod attest;
mod backend;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Backend attestation protocol that the server implements.
    #[clap(long = "protocol")]
    backend: ArgsBackend,

    /// UNIX domain socket path to the SVSM serial port
    #[clap(long)]
    unix: String,

    /// Force Unix domain socket removal before bind
    #[clap(long, short, default_value_t = false)]
    force: bool,
}

/// Enum to represent possible backends in the CLI.
/// This must not have any attached data to its variants for `ValueEnum`
/// to work.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ArgsBackend {
    Kbs,
}

fn accept_loop<S: Read + Write>(
    incoming: impl Iterator<Item = std::io::Result<S>>,
    url: &str,
    backend: ArgsBackend,
) -> anyhow::Result<()> {
    for stream in incoming {
        let mut stream = stream.context("Failed to accept connection")?;
        let mut http_client = backend::HttpClient::new(url.to_string(), backend.into())?;
        attest::attest(&mut stream, &mut http_client)?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.force {
        let _ = fs::remove_file(args.unix.clone());
    }

    let listener = UnixListener::bind(args.unix).context("unable to bind to UNIX socket")?;
    accept_loop(listener.incoming(), &args.url, args.backend)?;

    Ok(())
}
