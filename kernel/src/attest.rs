// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    error::SvsmError,
    greq::{
        pld_report::{SnpReportRequest, SnpReportResponse},
        services::get_regular_report,
    },
    io::{Read, Write, DEFAULT_IO_DRIVER},
    serial::SerialPort,
};
use aes::{cipher::BlockDecrypt, Aes128};
use aes_gcm::KeyInit;
use alloc::{string::ToString, vec, vec::Vec};
use base64::prelude::*;
use core::{cmp::min, fmt};
use kbs_types::Tee;
use libaproxy::*;
use p384::{ecdh, NistP384, PublicKey};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use rdrand::RdSeed;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zerocopy::{FromBytes, IntoBytes};

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[derive(Debug)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
}

impl TryFrom<Tee> for AttestationDriver<'_> {
    type Error = SvsmError;

    fn try_from(tee: Tee) -> Result<Self, Self::Error> {
        // TODO: Make the IO port configurable/discoverable for other transport mechanisms such as
        // virtio-vsock.
        let sp = SerialPort::new(&DEFAULT_IO_DRIVER, 0x3e8); // COM3
        sp.init();

        match tee {
            Tee::Snp => (),
            _ => return Err(AttestationError::UnsupportedTee.into()),
        }

        Ok(Self { sp, tee })
    }
}

impl AttestationDriver<'_> {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> Result<Vec<u8>, SvsmError> {
        let negotiation = self.negotiation()?;

        Ok(self.attestation(negotiation)?)
    }

    /// Send a negotiation request to the proxy. Proxy should reply with Negotiation parameters
    /// that should be included in attestation evidence (e.g. through SEV-SNP's REPORT_DATA
    /// mechanism).
    fn negotiation(&mut self) -> Result<NegotiationResponse, AttestationError> {
        let request = NegotiationRequest {
            version: "0.1.0".to_string(), // Only version supported at present.
            tee: self.tee,
        };

        self.write(request)?;
        let payload = self.read()?;

        serde_json::from_slice(&payload).or(Err(AttestationError::NegotiationDeserialize))
    }

    /// Send an attestation request to the proxy. Proxy should reply with attestation response
    /// containing the status (success/fail) and an optional secret returned from the server upon
    /// successful attestation.
    fn attestation(
        &mut self,
        negotiation: NegotiationResponse,
    ) -> Result<Vec<u8>, AttestationError> {
        // Generate TEE key and evidence for serialization to proxy.
        let key = self.tee_key_generate(&negotiation)?;
        let evidence = self.evidence(negotiation, &key)?;

        let request = AttestationRequest {
            evidence: BASE64_URL_SAFE.encode(evidence),
            key: AttestationKey::try_from(&key)?,
        };

        self.write(request)?;

        let payload = self.read()?;
        let response: AttestationResponse =
            serde_json::from_slice(&payload).or(Err(AttestationError::AttestationDeserialize))?;

        if !response.success {
            return Err(AttestationError::Failed);
        }

        self.secret_decrypt(response, &key)
    }

    /// Read attestation data from the serial port.
    fn read(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = {
            let mut bytes = [0u8; 8];
            self.sp
                .read(&mut bytes)
                .or(Err(AttestationError::ProxyRead))?;

            usize::from_ne_bytes(bytes)
        };

        let mut buf = vec![0u8; len];
        self.sp
            .read(&mut buf)
            .or(Err(AttestationError::ProxyRead))?;

        Ok(buf)
    }

    /// Write attestation data over the serial port.
    fn write(&mut self, param: impl Serialize) -> Result<(), AttestationError> {
        let bytes = serde_json::to_vec(&param).or(Err(AttestationError::NegotiationSerialize))?;

        // The receiving party is unaware of how many bytes to read from the port. Write an 8-byte
        // header indicating the length of the buffer before writing the buffer itself.
        self.sp
            .write(&bytes.len().to_ne_bytes())
            .or(Err(AttestationError::ProxyWrite))?;
        self.sp
            .write(&bytes)
            .or(Err(AttestationError::ProxyWrite))?;

        Ok(())
    }

    /// Generate the TEE attestation key.
    fn tee_key_generate(
        &self,
        negotiation: &NegotiationResponse,
    ) -> Result<TeeKey, AttestationError> {
        let key = match negotiation.key_type {
            NegotiationKey::Ecdh384Sha256Aes128 => TeeKey::ec(384)?,
        };

        Ok(key)
    }

    /// Hash negotiation parameters and fetch TEE evidence.
    fn evidence(
        &self,
        negotiation: NegotiationResponse,
        key: &TeeKey,
    ) -> Result<Vec<u8>, AttestationError> {
        let mut hash = match negotiation.hash {
            NegotiationHash::SHA384 => self.hash(&negotiation, key, Sha384::new())?,
            NegotiationHash::SHA512 => self.hash(&negotiation, key, Sha512::new())?,
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
                    let len =
                        get_regular_report(&mut buf).or(Err(AttestationError::SnpGetReport))?;

                    // We have the length of the response. The rest of the response is unused.
                    // Parse the SnpReportResponse from the slice of the buf containing the
                    // response (that is, &buf[0..len]).
                    let resp = SnpReportResponse::ref_from_bytes(&buf[..len])
                        .or(Err(AttestationError::SnpGetReport))?;

                    // Get the attestation report as bytes for serialization in the
                    // AttestationRequest.
                    resp.report().as_bytes().to_vec()
                };

                bytes
            }
            // We check for supported TEE architectures in the AttestationDriver's constructor.
            _ => unreachable!(),
        };

        Ok(evidence)
    }

    /// Hash the negotiation parameters from the attestation server for inclusion in the
    /// attestation evidence.
    fn hash(
        &self,
        n: &NegotiationResponse,
        key: &TeeKey,
        mut sha: impl Digest,
    ) -> Result<Vec<u8>, AttestationError> {
        for p in &n.params {
            match p {
                NegotiationParam::Base64StdBytes(s) => {
                    let decoded = BASE64_STANDARD
                        .decode(s)
                        .or(Err(AttestationError::NegotiationParamDecode))?;

                    sha.update(decoded);
                }
                #[allow(irrefutable_let_patterns)]
                NegotiationParam::EcPublicKeySec1Bytes => {
                    if let TeeKey::Ecdh384Sha256Aes128(ec) = key {
                        sha.update(ec.public_key().to_sec1_bytes());
                    } else {
                        return Err(AttestationError::ProxyRead);
                    }
                }
            }
        }

        Ok(sha.finalize().to_vec())
    }

    /// Decrypt a secret from the attestation server with the TEE private key.
    fn secret_decrypt(
        &self,
        resp: AttestationResponse,
        key: &TeeKey,
    ) -> Result<Vec<u8>, AttestationError> {
        let secret = resp.secret.ok_or(AttestationError::SecretMissing)?;

        match key {
            TeeKey::Ecdh384Sha256Aes128(ec) => {
                // Get the shared ECDH secret between the client/server EC keys.
                let shared = {
                    let s = resp.pub_key.ok_or(AttestationError::SecretDecrypt)?;
                    let pub_key =
                        PublicKey::from_sec1_bytes(&s).or(Err(AttestationError::SecretDecrypt))?;

                    ec.diffie_hellman(&pub_key)
                };

                // Extract the HKDF bytes and use to build an AES-128 symmetric key.
                let mut sha_bytes = [0u8; 16];
                let empty: [u8; 0] = [];

                let hkdf = shared.extract::<Sha256>(None);
                hkdf.expand(&empty, &mut sha_bytes)
                    .or(Err(AttestationError::SecretDecrypt))?;
                let aes =
                    Aes128::new_from_slice(&sha_bytes).or(Err(AttestationError::SecretDecrypt))?;

                // Decrypt each 16-byte block of the ciphertext with the symmetric key.
                let mut ptr = 0;
                let len = secret.len();
                let mut vec: Vec<u8> = Vec::new();
                while ptr < len {
                    let remain = min(16, len - ptr);
                    let mut arr: [u8; 16] = [0u8; 16];
                    arr[..remain].copy_from_slice(&secret[ptr..ptr + remain]);
                    aes.decrypt_block((&mut arr).into());
                    vec.append(&mut arr.to_vec());
                    ptr += remain;
                }

                Ok(vec)
            }
        }
    }
}

/// TEE key used to decrypt secrets sent from the attestation server.
pub enum TeeKey {
    Ecdh384Sha256Aes128(ecdh::EphemeralSecret),
}

impl TeeKey {
    /// Generate an Elliptic Curve key as the TEE key.
    fn ec(curve: usize) -> Result<Self, AttestationError> {
        let mut rdseed = RdSeed::new().or(Err(AttestationError::TeeKeyGenerate))?;
        let mut rng = ChaChaRng::from_rng(&mut rdseed).or(Err(AttestationError::TeeKeyGenerate))?;

        let key = match curve {
            384 => ecdh::EphemeralSecret::random(&mut rng),
            _ => unreachable!(),
        };

        Ok(Self::Ecdh384Sha256Aes128(key))
    }
}

impl fmt::Debug for TeeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Ecdh384Sha256Aes128(_) => write!(f, "EC384"),
        }
    }
}

impl TryFrom<&TeeKey> for AttestationKey {
    type Error = AttestationError;

    fn try_from(key: &TeeKey) -> Result<AttestationKey, Self::Error> {
        match key {
            TeeKey::Ecdh384Sha256Aes128(k) => {
                let jwk = k.public_key().to_jwk();
                let crv = jwk.crv().to_string();
                let epoint = jwk
                    .to_encoded_point::<NistP384>()
                    .or(Err(AttestationError::TeeKeyEncode))?;

                let x = epoint.x().ok_or(AttestationError::TeeKeyEncode)?;
                let y = epoint.y().ok_or(AttestationError::TeeKeyEncode)?;

                Ok(AttestationKey::EC {
                    crv,
                    x_b64url: BASE64_URL_SAFE.encode(x),
                    y_b64url: BASE64_URL_SAFE.encode(y),
                })
            }
        }
    }
}

/// Possible errors when attesting TEE evidence.
#[derive(Clone, Copy, Debug)]
pub enum AttestationError {
    /// Error deserializing the attestation response from JSON bytes.
    AttestationDeserialize,
    /// Unsuccessful attestation.
    Failed,
    /// Error deserializing the negotiation response from JSON bytes.
    NegotiationDeserialize,
    /// Error decoding a negotiation parameter.
    NegotiationParamDecode,
    /// Error serializing the negotiation request to JSON bytes.
    NegotiationSerialize,
    /// Error reading from the attestation proxy transport channel.
    ProxyRead,
    /// Error writing over the attestation proxy transport channel.
    ProxyWrite,
    /// Attestation successful, but unable to decrypt secret.
    SecretDecrypt,
    /// Attestation successful, but no secret found.
    SecretMissing,
    /// Error fetching the SEV-SNP attestation report.
    SnpGetReport,
    /// Error encoding the TEE public key to JSON.
    TeeKeyEncode,
    /// Error generating the TEE key.
    TeeKeyGenerate,
    /// Unsupported TEE architecture.
    UnsupportedTee,
}

impl From<AttestationError> for SvsmError {
    fn from(e: AttestationError) -> Self {
        Self::Attestation(e)
    }
}
