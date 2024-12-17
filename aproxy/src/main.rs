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
use std::{fs, os::unix::net::UnixListener, thread};

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

    let http = ProtocolDispatcher {
        url: args.url,
        attestation,
        negotiation,
    };

    {
        let mut backend = BACKEND.lock().unwrap();
        *backend = Some(http);
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || {
                    if let Err(e) = attest::attest(&mut stream) {
                        eprintln!("{e}");
                    }
                });
            }
            Err(_) => {
                panic!("error");
            }
        }
    }

    Ok(())
}
