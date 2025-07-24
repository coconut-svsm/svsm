// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    error::SvsmError,
    fw_cfg::FwCfg,
    greq::{pld_report::*, services::get_regular_report},
    io::{Read, Write, DEFAULT_IO_DRIVER},
    platform::SVSM_PLATFORM,
    serial::SerialPort,
    utils::vec::{try_to_vec, vec_sized},
};

#[cfg(feature = "vsock")]
use crate::vsock::virtio_vsock::VsockStream;

use aes::{cipher::BlockDecrypt, Aes256Dec};
use aes_gcm::KeyInit;
use alloc::{string::ToString, vec::Vec};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE},
    Engine,
};
use cocoon_tpm_crypto::{
    ecc::{curve::Curve, ecdh::ecdh_c_1e_1s_cdh_party_v_key_gen, EccKey},
    rng::{self, HashDrbg, RngCore as _, X86RdSeedRng},
    CryptoError, EmptyCryptoIoSlices,
};
use cocoon_tpm_tpm2_interface::{self as tpm2_interface, TpmEccCurve, TpmiAlgHash, TpmsEccPoint};
use cocoon_tpm_utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
};
use core::cmp::min;
use kbs_types::Tee;
use libaproxy::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use zerocopy::{FromBytes, IntoBytes};

enum Transport<'a> {
    #[cfg(feature = "vsock")]
    Vsock(VsockStream),
    Serial(SerialPort<'a>),
}

impl Transport<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        match self {
            #[cfg(feature = "vsock")]
            Transport::Vsock(vsock) => vsock.write(buf),
            Transport::Serial(serial) => serial.write(buf),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        match self {
            #[cfg(feature = "vsock")]
            Transport::Vsock(vsock) => vsock.read(buf),
            Transport::Serial(serial) => serial.read(buf),
        }
    }
}

fn create_serial_transport<'a>() -> Transport<'a> {
    let sp = SerialPort::new(&DEFAULT_IO_DRIVER, 0x3e8); // COM3
    sp.init();
    Transport::Serial(sp)
}

#[cfg(feature = "vsock")]
fn get_vsock_attest_port() -> u32 {
    const VSOCK_ATTEST_DEFAULT_PORT: u32 = 1995;

    FwCfg::new(SVSM_PLATFORM.get_io_port())
        .get_vsock_attest_port()
        .unwrap_or(VSOCK_ATTEST_DEFAULT_PORT)
}

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[allow(missing_debug_implementations)]
pub struct AttestationDriver<'a> {
    transport: Transport<'a>,
    tee: Tee,
    ecc: EccKey,
}

impl TryFrom<Tee> for AttestationDriver<'_> {
    type Error = SvsmError;

    fn try_from(tee: Tee) -> Result<Self, Self::Error> {
        // TODO: Make the IO port configurable/discoverable for other transport mechanisms such as
        // virtio-vsock.

        match tee {
            Tee::Snp => (),
            _ => return Err(AttestationError::UnsupportedTee.into()),
        }

        let curve = Curve::new(TpmEccCurve::NistP521).map_err(AttestationError::Crypto)?;
        let ecc = sc_key_generate(&curve).map_err(AttestationError::Crypto)?;

        let transport = {
            #[cfg(feature = "vsock")]
            {
                match VsockStream::connect(1234, get_vsock_attest_port(), 2) {
                    Ok(value) => Transport::Vsock(value),
                    Err(e) => {
                        log::warn!("Vsock Error: {:?} during attestation. Trying again using the serial port.", e);
                        create_serial_transport()
                    }
                }
            }
            #[cfg(not(feature = "vsock"))]
            {
                create_serial_transport()
            }
        };

        Ok(Self {
            transport,
            tee,
            ecc,
        })
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
    fn attestation(&mut self, n: NegotiationResponse) -> Result<Vec<u8>, AttestationError> {
        let curve =
            Curve::new(self.ecc.pub_key().get_curve_id()).map_err(AttestationError::Crypto)?;

        let pub_key = self
            .ecc
            .pub_key()
            .to_tpms_ecc_point(&curve.curve_ops().map_err(AttestationError::Crypto)?)
            .map_err(AttestationError::Crypto)?;

        let evidence = evidence(&self.tee, hash(n, &pub_key)?)?;

        let req = AttestationRequest {
            evidence: BASE64_URL_SAFE.encode(evidence),
            key: (self.ecc.pub_key().get_curve_id(), &pub_key)
                .try_into()
                .map_err(|_| AttestationError::AttestationDeserialize)?,
        };

        self.write(req)?;
        let payload = self.read()?;

        let response: AttestationResponse = serde_json::from_slice(&payload)
            .map_err(|_| AttestationError::AttestationDeserialize)?;

        if !response.success {
            return Err(AttestationError::Failed);
        }

        let Some(ak) = response.pub_key else {
            return Err(AttestationError::PublicKeyMissing)?;
        };

        let pub_key: TpmsEccPoint<'static> = ak.try_into().map_err(AttestationError::Crypto)?;

        let Some(ciphertext) = response.secret else {
            return Err(AttestationError::SecretMissing);
        };

        self.decrypt(ciphertext, pub_key)
    }

    /// Decrypt a secret from the attestation server with the TEE private key.
    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        pub_key: TpmsEccPoint<'static>,
    ) -> Result<Vec<u8>, AttestationError> {
        let shared_secret =
            ecdh_c_1e_1s_cdh_party_v_key_gen(TpmiAlgHash::Sha256, "", &self.ecc, &pub_key)
                .map_err(AttestationError::Crypto)?;

        let aes = Aes256Dec::new_from_slice(&shared_secret[..])
            .map_err(|_| AttestationError::AesGenerate)?;
        // Decrypt each 16-byte block of the ciphertext with the symmetric key.
        let mut ptr = 0;
        let len = ciphertext.len();
        let mut vec: Vec<u8> = Vec::new();
        while ptr < len {
            let remain = min(16, len - ptr);
            let mut arr: [u8; 16] = [0u8; 16];
            arr[..remain].copy_from_slice(&ciphertext[ptr..ptr + remain]);
            aes.decrypt_block((&mut arr).into());
            vec.append(&mut try_to_vec(&arr).or(Err(AttestationError::VecAlloc))?);
            ptr += remain;
        }

        Ok(vec)
    }

    /// Read attestation data from the serial port.
    fn read(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = {
            let mut bytes = [0u8; 8];
            self.transport
                .read(&mut bytes)
                .or(Err(AttestationError::ProxyRead))?;

            usize::from_ne_bytes(bytes)
        };

        let mut buf: Vec<u8> = vec_sized(len).or(Err(AttestationError::VecAlloc))?;

        self.transport
            .read(&mut buf)
            .or(Err(AttestationError::ProxyRead))?;

        Ok(buf)
    }

    /// Write attestation data over the serial port.
    fn write(&mut self, param: impl Serialize) -> Result<(), AttestationError> {
        let bytes = serde_json::to_vec(&param).or(Err(AttestationError::NegotiationSerialize))?;

        // The receiving party is unaware of how many bytes to read from the port. Write an 8-byte
        // header indicating the length of the buffer before writing the buffer itself.
        self.transport
            .write(&bytes.len().to_ne_bytes())
            .or(Err(AttestationError::ProxyWrite))?;
        self.transport
            .write(&bytes)
            .or(Err(AttestationError::ProxyWrite))?;

        Ok(())
    }
}

/// Possible errors when attesting TEE evidence.
#[derive(Clone, Copy, Debug)]
pub enum AttestationError {
    /// Error generating AES key.
    AesGenerate,
    /// Error deserializing the attestation response from JSON bytes.
    AttestationDeserialize,
    /// Guest has failed attestation.
    Failed,
    /// Error deserializing the negotiation response from JSON bytes.
    NegotiationDeserialize,
    /// Error serializing the negotiation request to JSON bytes.
    NegotiationSerialize,
    /// Error reading from the attestation proxy transport channel.
    ProxyRead,
    /// Error writing over the attestation proxy transport channel.
    ProxyWrite,
    /// Attestation successful, but no public key found.
    PublicKeyMissing,
    /// Unsupported TEE architecture.
    UnsupportedTee,
    /// Unable to generate secure channel key.
    Crypto(CryptoError),
    /// Attestation successful, but unable to decrypt secret.
    SecretDecrypt,
    /// Attestation successful, but no secret found.
    SecretMissing,
    /// Unable to fetch SEV-SNP attestation report.
    SnpGetReport,
    /// Unable to allocate memory for Vec.
    VecAlloc,
}

impl From<AttestationError> for SvsmError {
    fn from(e: AttestationError) -> Self {
        Self::TeeAttestation(e)
    }
}

/// Generate a key used to establish a secure channel between the confidential guest and
/// attestation server.
fn sc_key_generate(curve: &Curve) -> Result<EccKey, CryptoError> {
    let mut rng = {
        let mut rdseed = X86RdSeedRng::instantiate().map_err(|_| CryptoError::RngFailure)?;
        let mut hash_drbg_entropy =
            try_alloc_zeroizing_vec(HashDrbg::min_seed_entropy_len(TpmiAlgHash::Sha256))?;

        rdseed.generate::<_, EmptyCryptoIoSlices>(
            io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice())
                .map_infallible_err(),
            None,
        )?;

        rng::HashDrbg::instantiate(
            tpm2_interface::TpmiAlgHash::Sha256,
            &hash_drbg_entropy,
            None,
            Some(b"SVSM attestation RNG"),
        )
    }?;

    let curve_ops = curve.curve_ops()?;

    EccKey::generate(&curve_ops, &mut rng, None)
}

/// Hash negotiation parameters and fetch TEE evidence.
fn evidence(tee: &Tee, hash: Vec<u8>) -> Result<Vec<u8>, AttestationError> {
    let evidence = match tee {
        &Tee::Snp => {
            let mut user_data = [0u8; 64];
            user_data.copy_from_slice(&hash);

            let request = SnpReportRequest::new(user_data, 0, 1);

            let data = try_to_vec(request.as_bytes()).or(Err(AttestationError::VecAlloc))?;
            // The buffer currently contains the the SnpReportRequest structure. However, SVSM
            // will fill this buffer in with the SnpReportResponse when fetching the report.
            // Ensure the array is large enough to contain the response (which is much larger
            // than the request, as it contains the attestation report).
            let mut buf: Vec<u8> = vec_sized(2048).or(Err(AttestationError::VecAlloc))?;

            buf[..data.len()].copy_from_slice(&data);

            let len = get_regular_report(&mut buf).or(Err(AttestationError::SnpGetReport))?;

            // We have the length of the response. The rest of the response is unused.
            // Parse the SnpReportResponse from the slice of the buf containing the
            // response (that is, &buf[0..len]).
            let resp = SnpReportResponse::ref_from_bytes(&buf[..len])
                .or(Err(AttestationError::SnpGetReport))?;

            // Get the attestation report as bytes for serialization in the
            // AttestationRequest.
            try_to_vec(resp.report().as_bytes()).or(Err(AttestationError::VecAlloc))?
        }
        // We check for supported TEE architectures in the AttestationDriver's constructor.
        _ => unreachable!(),
    };

    Ok(evidence)
}

/// Hash the negotiation parameters from the attestation server for inclusion in the
/// attestation evidence.
fn hash(
    n: NegotiationResponse,
    pub_key: &TpmsEccPoint<'static>,
) -> Result<Vec<u8>, AttestationError> {
    let mut sha = Sha512::new();

    for p in &n.params {
        match p {
            NegotiationParam::Base64StdBytes(s) => {
                let decoded = BASE64_STANDARD
                    .decode(s)
                    .map_err(|_| AttestationError::NegotiationDeserialize)?;

                sha.update(decoded);
            }
            #[allow(irrefutable_let_patterns)]
            NegotiationParam::EcPublicKeyBytes => {
                sha.update(&*pub_key.x.buffer);
                sha.update(&*pub_key.y.buffer);
            }
        }
    }

    try_to_vec(&sha.finalize()).or(Err(AttestationError::VecAlloc))
}
