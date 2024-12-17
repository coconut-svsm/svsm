// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

mod attest;
mod backend;

use crate::backend::{kbs::KbsProtocol, *};
use anyhow::Context;
use clap::Parser;
use reqwest::{blocking::Client, cookie::Jar};
use std::{fs, mem, os::unix::net::UnixListener, sync::Arc, thread};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Backend attestation protocol that the server implements.
    #[clap(long = "protocol")]
    backend: Protocol,

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

    // Initialize UNIX listener for attestation requests from SVSM.
    let listener = UnixListener::bind(args.unix).context("unable to bind to UNIX socket")?;

    // Initialize HTTP socket for attestation server (with specific protocol).
    let (negotiation, attestation) = match args.backend {
        Protocol::Kbs => (KbsProtocol::negotiation, KbsProtocol::attestation),
    };

    let http = HttpClient {
        cli: Client::builder()
            .cookie_provider(Arc::new(Jar::default()))
            .build()
            .context("unable to build HTTP client to interact with attestation server")?,
        url: args.url,
        attestation,
        negotiation,
    };

    thread::spawn(move || {
        let mut backend = BACKEND.lock().unwrap();
        let _ = mem::replace(&mut *backend, Some(http));
    });

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                attest::attest(&mut stream)?;
            }
            Err(_) => {
                panic!("error");
            }
        }
    }

    Ok(())
}
