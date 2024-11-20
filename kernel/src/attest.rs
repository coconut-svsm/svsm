// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    greq::{
        pld_report::{SnpReportRequest, SnpReportResponse},
        services::get_regular_report,
    },
    io::{Read, Write, DEFAULT_IO_DRIVER},
    serial::SerialPort,
};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use base64::prelude::*;
use kbs_types::Tee;
use libaproxy::*;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use rdrand::RdSeed;
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use serde::Serialize;
use sha2::{Digest, Sha384, Sha512};
use zerocopy::{FromBytes, IntoBytes};

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[derive(Debug)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
    key: Option<TeeKey>,
}

impl From<Tee> for AttestationDriver<'_> {
    fn from(tee: Tee) -> Self {
        let sp = SerialPort::new(&DEFAULT_IO_DRIVER, 0x3e8); // COM3
        sp.init();

        Self { sp, tee, key: None }
    }
}

impl AttestationDriver<'_> {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> String {
        let negotiation = self.negotiation();
        let _result = self.attestation(negotiation);

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

        let response: NegotiationResponse = {
            let payload = self.read();

            serde_json::from_slice(&payload).unwrap()
        };

        response
    }

    /// Send an attestation request to the proxy. Proxy should reply with attestation response
    /// containing the status (success/fail) and an optional secret returned from the server upon
    /// successful attestation.
    fn attestation(&mut self, negotiation: NegotiationResponse) -> AttestationResponse {
        // Generate TEE key and evidence for serialization to proxy.
        self.tee_key_generate(&negotiation);
        let evidence = self.evidence(negotiation);

        let request = AttestationRequest {
            evidence: BASE64_STANDARD.encode(evidence),
            key: AttestationKey::from(&self.key.clone().unwrap()),
        };

        self.write(request);

        let response: AttestationResponse = {
            let payload = self.read();

            serde_json::from_slice(&payload).unwrap()
        };

        log::info!("{:?}", response);

        todo!();
    }

    /// Generate the TEE attestation key.
    fn tee_key_generate(&mut self, negotiation: &NegotiationResponse) {
        let key = match negotiation.key_type {
            NegotiationKey::RSA3072 => TeeKey::rsa(3072),
            NegotiationKey::RSA4096 => TeeKey::rsa(4096),
            _ => panic!("unsupported TEE key type selected"),
        };

        self.key = Some(key);
    }

    /// Hash negotiation parameters and fetch TEE evidence.
    fn evidence(&self, negotiation: NegotiationResponse) -> Vec<u8> {
        let mut hash = match negotiation.hash {
            NegotiationHash::SHA384 => self.hash(&negotiation, Sha384::new()),
            NegotiationHash::SHA512 => self.hash(&negotiation, Sha512::new()),
        };

        let evidence = match self.tee {
            Tee::Snp => {
                // SEV-SNP REPORT_DATA is 64 bytes in size. If a SHA384 was selected in the
                // negotiation parameters, that array is 48 bytes in size and must be padded.
                hash.resize(64, 0);

                let mut user_data = [0u8; 64];
                user_data.copy_from_slice(&hash);

                let request = SnpReportRequest {
                    user_data,
                    vmpl: 0,
                    flags: 1, // Sign with VCEK.
                    rsvd: [0u8; 24],
                };

                let mut buf = request.as_bytes().to_vec();
                // The buffer currently contains the the SnpReportRequest structure. However, SVSM
                // will fill this buffer in with the SnpReportResponse when fetching the report.
                // Ensure the array is large enough to contain the response (which is much larger
                // than the request, as it contains the attestation report).
                buf.resize(2048, 0);

                let bytes = {
                    let len = get_regular_report(&mut buf).unwrap();

                    // We have the length of the response. The rest of the response is unused.
                    // Parse the SnpReportResponse from the slice of the buf containing the
                    // response (that is, &buf[0..len]).
                    let resp = SnpReportResponse::ref_from_bytes(&buf[..len]).unwrap();

                    // Get the attestation report as bytes for serialization in the
                    // AttestationRequest.
                    resp.report().as_bytes().to_vec()
                };

                bytes
            }
            _ => panic!("invalid TEE architecture"),
        };

        evidence
    }

    /// Hash the negotiation parameters from the attestation server for inclusion in the
    /// attestation evidence.
    fn hash(&self, n: &NegotiationResponse, mut sha: impl Digest) -> Vec<u8> {
        for p in &n.params {
            match p {
                NegotiationParam::Base64StdBytes(s) => {
                    sha.update(BASE64_STANDARD.decode(s).unwrap())
                }
                NegotiationParam::TeeKeyPublicComponents => {
                    let key = &self.key.clone().unwrap();
                    key.hash(&mut sha);
                }
            }
        }

        sha.finalize().to_vec()
    }

    /// Read attestation data from the serial port.
    fn read(&mut self) -> Vec<u8> {
        let len = {
            let mut bytes = [0u8; 8];
            self.sp.read(&mut bytes).unwrap();

            usize::from_ne_bytes(bytes)
        };

        let mut buf = vec![0u8; len];
        self.sp.read(&mut buf).unwrap();

        buf
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

/// TEE key used to decrypt secrets sent from the attestation server.
#[derive(Clone, Debug)]
pub enum TeeKey {
    Rsa(RsaPrivateKey),
}

impl TeeKey {
    /// Generate an RSA key as the TEE key.
    fn rsa(bits: usize) -> Self {
        let mut rng = ChaChaRng::from_rng(&mut RdSeed::new().unwrap()).unwrap();

        let rsa = RsaPrivateKey::new(&mut rng, bits).unwrap();

        Self::Rsa(rsa)
    }

    /// Hash the public components of the TEE key.
    fn hash(&self, sha: &mut impl Digest) {
        match self {
            Self::Rsa(rsa) => {
                let public = rsa.to_public_key();

                sha.update(public.n().to_bytes_be());
                sha.update(public.e().to_bytes_be());
            }
        }
    }
}

impl From<&TeeKey> for AttestationKey {
    fn from(key: &TeeKey) -> AttestationKey {
        match key {
            TeeKey::Rsa(rsa) => {
                let public = rsa.to_public_key();

                AttestationKey::RSA {
                    n: BASE64_URL_SAFE.encode(public.n().to_bytes_be()),
                    e: BASE64_URL_SAFE.encode(public.e().to_bytes_be()),
                }
            }
        }
    }
}
