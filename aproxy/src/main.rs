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
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// HTTP url to KBS (e.g. http://server:4242)
    #[clap(long)]
    url: String,

    /// Backend attestation protocol that the server implements.
    /// Supported servers include:
    /// kbs-test: https://github.com/tylerfanelli/kbs-test (for testing).
    #[clap(long = "protocol")]
    backend: backend::Protocol,

    /// UNIX domain socket path to the SVSM serial port
    #[clap(
        long,
        conflicts_with = "vsock_port",
        required_unless_present("vsock_port")
    )]
    unix: Option<String>,

    /// vsock port used by SVSM for attestation
    #[clap(long, conflicts_with_all = ["unix", "force"], required_unless_present("unix"))]
    vsock_port: Option<u32>,

    /// Force Unix domain socket removal before bind
    #[clap(long, short, requires = "unix", default_value_t = false)]
    force: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.vsock_port.is_some() {
        let listener =
            VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, args.vsock_port.unwrap()))
                .context("bind and listen failed")?;
        for stream in listener.incoming() {
            let mut stream = stream.expect("Failed to connect to the vsock socket");
            let mut http_client = backend::HttpClient::new(args.url.clone(), args.backend)?;
            attest::attest(&mut stream, &mut http_client)?;
        }
    } else {
        let unix = args.unix.unwrap();

        if args.force {
            let _ = fs::remove_file(unix.clone());
        }

        let listener = UnixListener::bind(unix).context("unable to bind to UNIX socket")?;
        for stream in listener.incoming() {
            let mut stream = stream.expect("Failed to connect to the unix socket");
            let mut http_client = backend::HttpClient::new(args.url.clone(), args.backend)?;
            attest::attest(&mut stream, &mut http_client)?;
        }
    }

    Ok(())
}
