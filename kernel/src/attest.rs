// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    crypto::{SecretSlice, get_svsm_rng},
    error::SvsmError,
    greq::{pld_report::*, services::get_regular_report},
    io::{Read, Write},
    utils::vec::{try_to_vec, vec_sized},
};
#[cfg(feature = "attest-serial")]
use crate::{io::DEFAULT_IO_DRIVER, serial::SerialPort};
use crate::{vsock::VMADDR_CID_HOST, vsock::stream::VsockStream};
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, aead::generic_array::GenericArray};
use aes_kw::{KeyInit as _, KwAes256};
use alloc::{string::ToString, vec::Vec};
use cocoon_tpm_crypto::{
    CryptoError,
    ecc::{EccKey, curve::Curve, ecdh::ecdh_c_1_1_cdh_compute_z},
};
use cocoon_tpm_tpm2_interface::{TpmEccCurve, TpmsEccPoint};
use kbs_types::Tee;
use libaproxy::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD, *};
use serde::Serialize;
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "attest-serial")]
// TODO: Make the IO port configurable/discoverable or drop the support entirely.
const ATTEST_DEFAULT_SERIAL_IO_ADDR: u16 = 0x3e8; // COM3

const TEE_REPORT_DATA_LEN: usize = 64;

enum Transport {
    Vsock(VsockStream),
    #[cfg(feature = "attest-serial")]
    Serial(SerialPort<'static>),
}

impl Read for Transport {
    type Err = SvsmError;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        match self {
            Transport::Vsock(vsock) => vsock.read(buf),
            #[cfg(feature = "attest-serial")]
            Transport::Serial(serial) => serial.read(buf),
        }
    }
}

impl Write for Transport {
    type Err = SvsmError;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        match self {
            Transport::Vsock(vsock) => vsock.write(buf),
            #[cfg(feature = "attest-serial")]
            Transport::Serial(serial) => serial.write(buf),
        }
    }
}

impl Transport {
    fn new() -> Result<Self, SvsmError> {
        match VsockStream::connect(ATTEST_DEFAULT_VSOCK_PORT, VMADDR_CID_HOST) {
            Ok(value) => Ok(Transport::Vsock(value)),
            Err(e) => {
                log::warn!(
                    "Failed to connect to attestation proxy on vsock port \
                     {ATTEST_DEFAULT_VSOCK_PORT}: {e:?}."
                );

                #[cfg(feature = "attest-serial")]
                {
                    log::warn!("Falling back to serial port transport.");
                    create_serial_transport()
                }
                #[cfg(not(feature = "attest-serial"))]
                Err(e)
            }
        }
    }
}

#[cfg(feature = "attest-serial")]
fn create_serial_transport() -> Result<Transport, SvsmError> {
    let sp = SerialPort::new(&DEFAULT_IO_DRIVER, ATTEST_DEFAULT_SERIAL_IO_ADDR);
    sp.init();
    Ok(Transport::Serial(sp))
}

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[allow(missing_debug_implementations)]
pub struct AttestationDriver {
    transport: Transport,
    tee: Tee,
    ecc: EccKey,
    auth_endpoint: alloc::string::String,
    attest_endpoint: alloc::string::String,
    resource_endpoint: alloc::string::String,
}

impl TryFrom<Tee> for AttestationDriver {
    type Error = SvsmError;

    fn try_from(tee: Tee) -> Result<Self, Self::Error> {
        match tee {
            Tee::Snp => (),
            _ => return Err(AttestationError::UnsupportedTee.into()),
        }

        let curve = Curve::new(TpmEccCurve::NistP521).map_err(AttestationError::Crypto)?;
        let ecc = sc_key_generate(&curve).map_err(AttestationError::Crypto)?;

        let transport = Transport::new()?;
        Ok(Self {
            transport,
            tee,
            ecc,
            auth_endpoint: "".to_string(),
            attest_endpoint: "".to_string(),
            resource_endpoint: "".to_string(),
        })
    }
}

impl AttestationDriver {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> Result<SecretSlice, SvsmError> {
        let config = self.handshake()?;

        let (nonce, params) = self.auth(config.payload_format)?;

        let curve =
            Curve::new(self.ecc.pub_key().get_curve_id()).map_err(AttestationError::Crypto)?;

        let pub_key = self
            .ecc
            .pub_key()
            .to_tpms_ecc_point(&curve.curve_ops().map_err(AttestationError::Crypto)?)
            .map_err(AttestationError::Crypto)?;

        let formatted_bytes = match config.payload_format {
            PayloadFormat::RawBinary => {
                let params = params.ok_or(AttestationError::NegotiationDeserialize)?;
                let formatter = RawBinaryFormatter { params };
                formatter.format(&nonce, &pub_key)?
            }
            PayloadFormat::JwsJson => {
                let formatter = JwsJsonFormatter;
                formatter.format(&nonce, &pub_key)?
            }
        };

        let digest = config.hash_algo.digest(&formatted_bytes);
        let evidence = evidence(&self.tee, prepare_report_data(&digest)?)?;

        let kbs_pub_key = (self.ecc.pub_key().get_curve_id(), &pub_key).into();
        self.attest_kbs(&nonce, evidence, kbs_pub_key)?;

        let secret = self.retrieve_secret()?;

        Ok(secret)
    }

    fn handshake(&mut self) -> Result<ConfigResponse, AttestationError> {
        let request = ConfigRequest {
            version: (0, 1, 0),
            tee: self.tee,
        };

        self.write(request)?;
        let payload = self.read()?;

        let config: ConfigResponse =
            serde_json::from_slice(&payload).or(Err(AttestationError::NegotiationDeserialize))?;

        self.auth_endpoint = config.auth_endpoint.clone();
        self.attest_endpoint = config.attest_endpoint.clone();
        self.resource_endpoint = config.resource_endpoint.clone();

        Ok(config)
    }

    fn auth(
        &mut self,
        format: PayloadFormat,
    ) -> Result<(Vec<u8>, Option<Vec<NegotiationParam>>), AttestationError> {
        let req = kbs_types::Request {
            version: "0.4.0".to_string(),
            tee: self.tee,
            extra_params: serde_json::Value::Null,
        };

        let proxy_req = ProxyRequest {
            endpoint: self.auth_endpoint.clone(),
            method: HttpMethod::POST,
            body: serde_json::to_value(&req).map_err(|_| AttestationError::NegotiationSerialize)?,
        };

        self.write(proxy_req)?;
        let payload = self.read()?;

        let proxy_resp: ProxyResponse = serde_json::from_slice(&payload)
            .map_err(|_| AttestationError::NegotiationDeserialize)?;

        if proxy_resp.status != 200 {
            return Err(AttestationError::Failed);
        }

        match format {
            PayloadFormat::JwsJson => {
                let challenge: kbs_types::Challenge = serde_json::from_str(&proxy_resp.body)
                    .map_err(|_| AttestationError::NegotiationDeserialize)?;

                let decoded_nonce = BASE64_STANDARD
                    .decode(&challenge.nonce)
                    .map_err(|_| AttestationError::NegotiationDeserialize)?;

                Ok((decoded_nonce, None))
            }
            PayloadFormat::RawBinary => {
                let challenge: LegacyChallenge = serde_json::from_str(&proxy_resp.body)
                    .map_err(|_| AttestationError::NegotiationDeserialize)?;

                let decoded_nonce = BASE64_STANDARD
                    .decode(&challenge.nonce)
                    .map_err(|_| AttestationError::NegotiationDeserialize)?;

                Ok((decoded_nonce, Some(challenge.params)))
            }
        }
    }

    fn attest_kbs(
        &mut self,
        challenge: &[u8],
        evidence: AttestationEvidence,
        pub_key: EcP256PublicKey,
    ) -> Result<(), AttestationError> {
        use kbs_types::{Attestation, CompositeEvidence, RuntimeData};

        let primary_evidence =
            serde_json::to_value(&evidence).map_err(|_| AttestationError::NegotiationSerialize)?;

        let attestation = Attestation {
            init_data: None,
            runtime_data: RuntimeData {
                nonce: BASE64_STANDARD.encode(challenge),
                tee_pubkey: pub_key.into(),
            },
            tee_evidence: CompositeEvidence {
                primary_evidence,
                additional_evidence: "".to_string(),
            },
        };

        let proxy_req = ProxyRequest {
            endpoint: self.attest_endpoint.clone(),
            method: HttpMethod::POST,
            body: serde_json::to_value(&attestation)
                .map_err(|_| AttestationError::NegotiationSerialize)?,
        };

        self.write(proxy_req)?;
        let payload = self.read()?;

        let proxy_resp: ProxyResponse = serde_json::from_slice(&payload)
            .map_err(|_| AttestationError::NegotiationDeserialize)?;

        if proxy_resp.status != 200 {
            return Err(AttestationError::Failed);
        }

        Ok(())
    }

    fn retrieve_secret(&mut self) -> Result<SecretSlice, AttestationError> {
        let proxy_req = ProxyRequest {
            endpoint: self.resource_endpoint.clone(),
            method: HttpMethod::GET,
            body: serde_json::Value::Null,
        };

        self.write(proxy_req)?;
        let payload = self.read()?;

        let proxy_resp: ProxyResponse = serde_json::from_slice(&payload)
            .map_err(|_| AttestationError::NegotiationDeserialize)?;

        if proxy_resp.status != 200 {
            return Err(AttestationError::Failed);
        }

        let kbs_resp: kbs_types::Response = serde_json::from_str(&proxy_resp.body)
            .map_err(|_| AttestationError::NegotiationDeserialize)?;

        let decoded_ciphertext = BASE64_STANDARD
            .decode(&kbs_resp.ciphertext)
            .map_err(|_| AttestationError::NegotiationDeserialize)?;

        let mut secret_slice = SecretSlice::from(decoded_ciphertext.into_boxed_slice());

        let epk = unwrap_epk(&kbs_resp)?;

        let aad = kbs_resp
            .protected
            .generate_aad()
            .map_err(|_| AttestationError::CekUnwrap)?;

        let decryption = AesGcmData {
            epk,
            wrapped_cek: kbs_resp.encrypted_key,
            aad,
            iv: kbs_resp.iv,
            tag: kbs_resp.tag,
        };

        self.decrypt(&mut secret_slice, decryption)?;

        Ok(secret_slice)
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

        let wrapping_key: KwAes256 = {
            let mut buf = SecretSlice::new_sized(32).or(Err(AttestationError::VecAlloc))?;

            concat_kdf::derive_key_into::<sha2::Sha256>(&z, &kdm, &mut buf)
                .map_err(AttestationError::KeyDerivation)?;

            KwAes256::new_from_slice(&buf).or(Err(AttestationError::WrapKeyArrayConvert))
        }?;

        let mut cek = SecretSlice::new_sized(&decryption.wrapped_cek.len() - 8)
            .or(Err(AttestationError::VecAlloc))?;

        wrapping_key
            .unwrap_key(&decryption.wrapped_cek, &mut cek)
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

    /// Read attestation data from the transport channel.
    fn read(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = {
            let mut bytes = [0u8; 8];
            self.transport
                .read_exact(&mut bytes)
                .or(Err(AttestationError::ProxyRead))?;

            usize::from_ne_bytes(bytes)
        };

        let mut buf: Vec<u8> = vec_sized(len).or(Err(AttestationError::VecAlloc))?;

        self.transport
            .read_exact(&mut buf)
            .or(Err(AttestationError::ProxyRead))?;

        Ok(buf)
    }

    /// Write attestation data over the transport channel.
    fn write(&mut self, param: impl Serialize) -> Result<(), AttestationError> {
        let bytes = serde_json::to_vec(&param).or(Err(AttestationError::NegotiationSerialize))?;

        // The receiving party is unaware of how many bytes to read from the port. Write an 8-byte
        // header indicating the length of the buffer before writing the buffer itself.
        self.transport
            .write_all(&bytes.len().to_ne_bytes())
            .or(Err(AttestationError::ProxyWrite))?;
        self.transport
            .write_all(&bytes)
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
    /// Invalid challenge length detected.
    InvalidChallengeLength,
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
    let mut rng = get_svsm_rng()?;
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

trait PayloadFormatter {
    fn format(
        &self,
        challenge: &[u8],
        pub_key: &TpmsEccPoint<'_>,
    ) -> Result<Vec<u8>, AttestationError>;
}

struct RawBinaryFormatter {
    params: Vec<NegotiationParam>,
}

impl PayloadFormatter for RawBinaryFormatter {
    fn format(
        &self,
        challenge: &[u8],
        pub_key: &TpmsEccPoint<'_>,
    ) -> Result<Vec<u8>, AttestationError> {
        let mut buffer = Vec::new();

        for p in &self.params {
            match p {
                NegotiationParam::Challenge => {
                    buffer.extend_from_slice(challenge);
                }
                #[allow(irrefutable_let_patterns)]
                NegotiationParam::EcPublicKeyBytes => {
                    buffer.extend_from_slice(&pub_key.x.buffer);
                    buffer.extend_from_slice(&pub_key.y.buffer);
                }
            }
        }

        Ok(buffer)
    }
}

struct JwsJsonFormatter;

impl PayloadFormatter for JwsJsonFormatter {
    fn format(
        &self,
        challenge: &[u8],
        pub_key: &TpmsEccPoint<'_>,
    ) -> Result<Vec<u8>, AttestationError> {
        use alloc::collections::BTreeMap;
        use serde_json::json;

        let x_encoded = BASE64_URL_SAFE_NO_PAD.encode(&*pub_key.x.buffer);
        let y_encoded = BASE64_URL_SAFE_NO_PAD.encode(&*pub_key.y.buffer);
        let nonce_encoded = BASE64_STANDARD.encode(challenge);

        let mut key_map = BTreeMap::new();
        key_map.insert("alg".to_string(), json!("ECDH-ES+A256KW"));
        key_map.insert("crv".to_string(), json!("P-521"));
        key_map.insert("kty".to_string(), json!("EC"));
        key_map.insert("x".to_string(), json!(x_encoded));
        key_map.insert("y".to_string(), json!(y_encoded));

        let mut runtime_data = BTreeMap::new();
        runtime_data.insert("additional-evidence".to_string(), json!(""));
        runtime_data.insert("nonce".to_string(), json!(nonce_encoded));
        runtime_data.insert("tee-pubkey".to_string(), json!(key_map));

        serde_json::to_vec(&runtime_data).map_err(|_| AttestationError::NegotiationSerialize)
    }
}

fn unwrap_epk(resp: &kbs_types::Response) -> Result<EcP256PublicKey, AttestationError> {
    let epk = resp
        .protected
        .other_fields
        .get("epk")
        .ok_or(AttestationError::PublicKeyMissing)?;

    let x_str = epk
        .get("x")
        .ok_or(AttestationError::PublicKeyMissing)?
        .as_str()
        .ok_or(AttestationError::PublicKeyMissing)?;

    let y_str = epk
        .get("y")
        .ok_or(AttestationError::PublicKeyMissing)?
        .as_str()
        .ok_or(AttestationError::PublicKeyMissing)?;

    let x = BASE64_URL_SAFE_NO_PAD
        .decode(x_str)
        .map_err(|_| AttestationError::PublicKeyMissing)?;

    let y = BASE64_URL_SAFE_NO_PAD
        .decode(y_str)
        .map_err(|_| AttestationError::PublicKeyMissing)?;

    Ok(EcP256PublicKey { x, y })
}

/// Take variable-sized negotiation challenge nonce from aproxy into 64 byte array required
/// for the TEE attestation evidence report
fn prepare_report_data(challenge_digest: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if challenge_digest.len() > TEE_REPORT_DATA_LEN {
        return Err(AttestationError::InvalidChallengeLength);
    }

    let mut report_data = [0u8; TEE_REPORT_DATA_LEN];
    report_data[..challenge_digest.len()].copy_from_slice(challenge_digest);

    Ok(report_data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use cocoon_tpm_tpm2_interface::{Tpm2bEccParameter, TpmBuffer};

    fn make_ecc_point(x: &[u8], y: &[u8]) -> TpmsEccPoint<'static> {
        TpmsEccPoint {
            x: Tpm2bEccParameter {
                buffer: TpmBuffer::Owned(x.to_vec()),
            },
            y: Tpm2bEccParameter {
                buffer: TpmBuffer::Owned(y.to_vec()),
            },
        }
    }

    #[test]
    fn test_raw_binary_formatter() {
        let challenge = vec![0xdd; 48];
        let x = vec![0x10; 66];
        let y = vec![0x20; 66];
        let pub_key = make_ecc_point(&x, &y);

        let formatter = RawBinaryFormatter {
            params: vec![
                NegotiationParam::EcPublicKeyBytes,
                NegotiationParam::Challenge,
            ],
        };
        let formatted = formatter.format(&challenge, &pub_key).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&x);
        expected.extend_from_slice(&y);
        expected.extend_from_slice(&challenge);

        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_jws_json_formatter() {
        let challenge = vec![0xdd; 48];
        let x = vec![0x10; 66];
        let y = vec![0x20; 66];
        let pub_key = make_ecc_point(&x, &y);

        let formatter = JwsJsonFormatter;
        let formatted = formatter.format(&challenge, &pub_key).unwrap();

        let json_val: serde_json::Value = serde_json::from_slice(&formatted).unwrap();
        assert_eq!(
            json_val["nonce"].as_str().unwrap(),
            BASE64_STANDARD.encode(&challenge)
        );
        assert_eq!(
            json_val["tee-pubkey"]["alg"].as_str().unwrap(),
            "ECDH-ES+A256KW"
        );
        assert_eq!(json_val["additional-evidence"].as_str().unwrap(), "");
    }
}
