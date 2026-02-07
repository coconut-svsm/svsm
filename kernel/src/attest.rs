// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    error::SvsmError,
    greq::{pld_report::*, services::get_regular_report},
    io::{DEFAULT_IO_DRIVER, Read, Write},
    serial::SerialPort,
    utils::vec::{try_to_vec, vec_sized},
};
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, aead::generic_array::GenericArray};
use aes_kw::{Kek, KekAes256};
use alloc::{string::ToString, vec::Vec};
use cocoon_tpm_crypto::{
    CryptoError, EmptyCryptoIoSlices,
    ecc::{EccKey, curve::Curve, ecdh::ecdh_c_1_1_cdh_compute_z},
    rng::{self, HashDrbg, RngCore as _, X86RdSeedRng},
};
use cocoon_tpm_tpm2_interface::{self as tpm2_interface, TpmEccCurve, TpmiAlgHash, TpmsEccPoint};
use cocoon_tpm_utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
};
use kbs_types::Tee;
use libaproxy::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use zerocopy::{FromBytes, IntoBytes};

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[allow(missing_debug_implementations)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
    ecc: EccKey,
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

        let curve = Curve::new(TpmEccCurve::NistP521).map_err(AttestationError::Crypto)?;
        let ecc = sc_key_generate(&curve).map_err(AttestationError::Crypto)?;

        Ok(Self { sp, tee, ecc })
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
            version: (0, 1, 0), // Only version supported at present.
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

        let evidence = evidence(&self.tee, hash(&n, &pub_key)?)?;

        let req = AttestationRequest {
            tee: self.tee,
            evidence,
            challenge: n.challenge.clone(),
            key: (self.ecc.pub_key().get_curve_id(), &pub_key).into(),
        };

        self.write(req)?;
        let payload = self.read()?;

        let response: AttestationResponse = serde_json::from_slice(&payload)
            .map_err(|_| AttestationError::AttestationDeserialize)?;

        if !response.success {
            return Err(AttestationError::Failed);
        }

        let Some(decryption) = response.decryption else {
            return Err(AttestationError::PublicKeyMissing)?;
        };

        let Some(mut secret) = response.secret else {
            return Err(AttestationError::SecretMissing);
        };

        self.decrypt(&mut secret, decryption)?;

        Ok(secret)
    }

    /// Decrypt a secret from the attestation server with the TEE private key. Secrets are
    /// encrypted with ECDH-ES+A256KW as described in RFC 7518, section 4.6.2.
    fn decrypt(&self, secret: &mut [u8], decryption: AesGcmData) -> Result<(), AttestationError> {
        let epk: TpmsEccPoint<'static> = decryption.epk.into();
        let z = ecdh_c_1_1_cdh_compute_z(&self.ecc, &epk).map_err(AttestationError::Crypto)?;

        let mut kdm = Vec::new();
        let alg_str = "ECDH-ES+A256KW".to_string();

        kdm.extend_from_slice(&(alg_str.len() as u32).to_be_bytes());
        kdm.extend_from_slice(alg_str.as_bytes());
        kdm.extend_from_slice(&(0_u32).to_be_bytes());
        kdm.extend_from_slice(&(0_u32).to_be_bytes());
        kdm.extend_from_slice(&(256_u32).to_be_bytes());

        let wrapping_key: KekAes256 = {
            let mut buf: Vec<u8> = vec_sized(32).or(Err(AttestationError::VecAlloc))?;

            concat_kdf::derive_key_into::<sha2::Sha256>(&z, &kdm, &mut buf)
                .map_err(AttestationError::KeyDerivation)?;

            let sized: [u8; 32] = buf
                .try_into()
                .or(Err(AttestationError::WrapKeyArrayConvert))?;

            Kek::new(&GenericArray::from(sized))
        };

        let mut cek =
            vec_sized(&decryption.wrapped_cek.len() - 8).or(Err(AttestationError::VecAlloc))?;

        wrapping_key
            .unwrap(&decryption.wrapped_cek, &mut cek)
            .or(Err(AttestationError::CekUnwrap))?;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));

        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&decryption.iv),
                &decryption.aad,
                secret,
                GenericArray::from_slice(&decryption.tag),
            )
            .map_err(AttestationError::SecretDecrypt)?;

        Ok(())
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

        let mut buf: Vec<u8> = vec_sized(len).or(Err(AttestationError::VecAlloc))?;

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
}

/// Possible errors when attesting TEE evidence.
#[derive(Clone, Copy, Debug)]
pub enum AttestationError {
    /// Error generating AES key.
    AesGenerate,
    /// Error deserializing the attestation response from JSON bytes.
    AttestationDeserialize,
    // Unable to unwrap Content Encryption Key (CEK).
    CekUnwrap,
    /// Unable to generate secure channel key.
    Crypto(CryptoError),
    /// Guest has failed attestation.
    Failed,
    // Unable to derive wrap key.
    KeyDerivation(concat_kdf::Error),
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
    /// Attestation successful, but unable to decrypt secret.
    SecretDecrypt(aes_gcm::Error),
    /// Attestation successful, but no secret found.
    SecretMissing,
    /// Unable to fetch SEV-SNP attestation report.
    SnpGetReport,
    /// Unsupported TEE architecture.
    UnsupportedTee,
    /// Unable to allocate memory for Vec.
    VecAlloc,
    // Unable to convert wrap key to 32 byte array.
    WrapKeyArrayConvert,
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
fn evidence(tee: &Tee, hash: Vec<u8>) -> Result<AttestationEvidence, AttestationError> {
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
            let report =
                try_to_vec(resp.report().as_bytes()).or(Err(AttestationError::VecAlloc))?;

            AttestationEvidence::Snp {
                report,
                certs_buf: None,
            }
        }
        // We check for supported TEE architectures in the AttestationDriver's constructor.
        _ => unreachable!(),
    };

    Ok(evidence)
}

/// Hash the negotiation parameters from the attestation server for inclusion in the
/// attestation evidence.
fn hash(
    n: &NegotiationResponse,
    pub_key: &TpmsEccPoint<'static>,
) -> Result<Vec<u8>, AttestationError> {
    let mut sha = Sha512::new();

    for p in &n.params {
        match p {
            NegotiationParam::Challenge => {
                sha.update(&n.challenge);
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
