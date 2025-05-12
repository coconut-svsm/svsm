// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    error::SvsmError,
    io::{Read, Write, DEFAULT_IO_DRIVER},
    serial::SerialPort,
};
use alloc::{string::ToString, vec, vec::Vec};
use cocoon_tpm_crypto::{
    ecc,
    rng::{self, HashDrbg, RngCore as _, X86RdSeedRng},
    CryptoError, EmptyCryptoIoSlices,
};
use cocoon_tpm_tpm2_interface::{
    self as tpm2_interface, Tpm2bEccParameter, TpmEccCurve, TpmiAlgHash, TpmsEccPoint,
};
use cocoon_tpm_utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
};
use kbs_types::Tee;
use libaproxy::*;
use serde::Serialize;

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[derive(Debug)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
    _pub_key: TpmsEccPoint<'static>,
    _priv_key: Tpm2bEccParameter<'static>,
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

        let key = sc_key_generate(TpmEccCurve::NistP384).map_err(AttestationError::KeyGen)?;

        Ok(Self {
            sp,
            tee,
            _pub_key: key.0,
            _priv_key: key.1,
        })
    }
}

impl AttestationDriver<'_> {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> Result<Vec<u8>, SvsmError> {
        let _negotiation = self.negotiation()?;

        todo!();
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
}

/// Possible errors when attesting TEE evidence.
#[derive(Clone, Copy, Debug)]
pub enum AttestationError {
    /// Error deserializing the negotiation response from JSON bytes.
    NegotiationDeserialize,
    /// Error serializing the negotiation request to JSON bytes.
    NegotiationSerialize,
    /// Error reading from the attestation proxy transport channel.
    ProxyRead,
    /// Error writing over the attestation proxy transport channel.
    ProxyWrite,
    /// Unsupported TEE architecture.
    UnsupportedTee,
    /// Unable to generate secure channel key.
    KeyGen(CryptoError),
}

impl From<AttestationError> for SvsmError {
    fn from(e: AttestationError) -> Self {
        Self::TeeAttestation(e)
    }
}

/// Generate a key used to establish a secure channel between the confidential guest and
/// attestation server.
fn sc_key_generate(
    curve_id: TpmEccCurve,
) -> Result<(TpmsEccPoint<'static>, Tpm2bEccParameter<'static>), CryptoError> {
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

    let curve = ecc::curve::Curve::new(curve_id)?;
    let curve_ops = curve.curve_ops()?;
    let ecc_key = ecc::EccKey::generate(&curve_ops, &mut rng, None)?;

    let (pub_key, priv_key) = ecc_key.into_tpms(&curve_ops)?;

    let priv_key = priv_key.ok_or(CryptoError::Internal)?;

    Ok((pub_key, priv_key))
}
