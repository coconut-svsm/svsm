// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    io::DEFAULT_IO_DRIVER,
    serial::{SerialPort, Write},
};
use alloc::string::{String, ToString};
use kbs_types::Tee;
use libaproxy::*;
use serde::Serialize;

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[derive(Debug)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
}

impl From<Tee> for AttestationDriver<'_> {
    fn from(tee: Tee) -> Self {
        let sp = SerialPort::new(&DEFAULT_IO_DRIVER, 0x3e8); // COM3
        sp.init();

        Self { sp, tee }
    }
}

impl AttestationDriver<'_> {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> String {
        let _negotiation = self.negotiation();

        todo!();
    }

    /// Send a negotiation request to the proxy. Proxy should reply with Negotiation parameters
    /// that should be included in attestation evidence (e.g. through SEV-SNP's REPORT_DATA
    /// mechanism).
    fn negotiation(&mut self) -> NegotiationResponse {
        let request = NegotiationRequest {
            version: "0.1.0".to_string(), // Only version supported at present.
            tee: self.tee,
        };

        self.write(request);

        todo!();
    }

    /// Write attestation data over the serial port.
    fn write(&mut self, param: impl Serialize) {
        let bytes = serde_json::to_vec(&param).unwrap();

        // The receiving party is unaware of how many bytes to read from the port. Write an 8-byte
        // header indicating the length of the buffer before writing the buffer itself.
        self.sp.write(&bytes.len().to_ne_bytes()).unwrap();
        self.sp.write(&bytes).unwrap();
    }
}
