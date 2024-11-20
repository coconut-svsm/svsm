// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod attest;
mod backend;

use anyhow::Context;
use clap::Parser;
use std::{fs, os::unix::net::UnixListener};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Backend attestation protocol that the server implements.
    #[clap(long = "protocol")]
    backend: backend::Protocol,

    /// UNIX domain socket path to the SVSM serial port
    #[clap(long)]
    unix: String,

    /// Force Unix domain socket removal before bind
    #[clap(long, short, default_value_t = false)]
    force: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.force {
        let _ = fs::remove_file(args.unix.clone());
    }

    let listener = UnixListener::bind(args.unix).context("unable to bind to UNIX socket")?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut http_client = backend::HttpClient::new(args.url.clone(), args.backend)?;
                attest::attest(&mut stream, &mut http_client)?;
            }
            Err(_) => {
                panic!("error");
            }
        }
    }

    Ok(())
}
