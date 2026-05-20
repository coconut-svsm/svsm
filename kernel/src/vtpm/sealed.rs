// SPDX-License-Identifier: MIT
//
// Two-layer sealed container for vTPM persistent state.
//
// Architecture:
//   1. AES-256-GCM encrypts the full VtpmState (bulk data).
//   2. The 60-byte key bundle (aes_key || gcm_tag || nonce) is sealed by
//      the external TPM via TpmProxy.
//
// The TPM-sealed payload is kept small (60 bytes) to fit within the
// RSA-2048 / ECC seal size limit imposed by typical TPM sealing parents,
// while the bulk state travels under AES-GCM authenticated encryption.

extern crate alloc;

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::proxy::{TpmProxy, TpmTransport};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

// ============================================================
// Constants
// ============================================================

/// Size of the TPM seal payload: aes_key(32) + gcm_tag(16) + nonce(12) = 60 bytes
pub const SEAL_PAYLOAD_SIZE: usize = 60;
const GCM_TAG_SIZE: usize = 16;

/// Current SealedBlob format version
const BLOB_VERSION: u16 = 1;

// ============================================================
// VtpmState — Serializable vTPM Persistent State
// ============================================================

/// Serializable representation of vTPM persistent state.
///
/// Captures everything needed to restore vTPM identity across reboots:
/// EK, SRK, and persistent NV indices.
#[derive(Debug, Clone)]
pub struct VtpmState {
    /// Endorsement Key private (TPM2B_SENSITIVE)
    pub ek_priv: Vec<u8>,
    /// Endorsement Key public (TPM2B_PUBLIC / TPMT_PUBLIC)
    pub ek_pub: Vec<u8>,
    /// Storage Root Key private
    pub srk_priv: Vec<u8>,
    /// Storage Root Key public
    pub srk_pub: Vec<u8>,
    /// Owner hierarchy auth value
    pub owner_auth: [u8; 32],
    /// Endorsement hierarchy auth value
    pub endorsement_auth: [u8; 32],
    /// Lockout auth value
    pub lockout_auth: [u8; 32],
    /// Persistent NV data (concatenated NV indices)
    pub nv_data: Vec<u8>,
    /// Counter for persistent NV indices
    pub nv_counter: u32,
    /// Platform auth value
    pub platform_auth: [u8; 32],
    /// Opaque extra data
    pub extra: Vec<u8>,
}

impl VtpmState {
    /// Serialize VtpmState to a byte vector.
    #[inline] // R1: avoid sret aggregate-return on Vec<u8>
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);

        out.extend_from_slice(&(self.ek_priv.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ek_priv);

        out.extend_from_slice(&(self.ek_pub.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ek_pub);

        out.extend_from_slice(&(self.srk_priv.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.srk_priv);

        out.extend_from_slice(&(self.srk_pub.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.srk_pub);

        out.extend_from_slice(&self.owner_auth);
        out.extend_from_slice(&self.endorsement_auth);
        out.extend_from_slice(&self.lockout_auth);

        out.extend_from_slice(&self.nv_counter.to_le_bytes());

        out.extend_from_slice(&(self.nv_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.nv_data);

        out.extend_from_slice(&self.platform_auth);

        out.extend_from_slice(&(self.extra.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.extra);

        out
    }

    /// Deserialize VtpmState from bytes.
    #[inline] // R1: avoid sret aggregate-return on VtpmState
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let (ek_priv, offset) = read_len_prefixed(data, 0)?;
        let (ek_pub, offset) = read_len_prefixed(data, offset)?;
        let (srk_priv, offset) = read_len_prefixed(data, offset)?;
        let (srk_pub, offset) = read_len_prefixed(data, offset)?;

        if offset + 96 > data.len() {
            return Err("buffer underrun at auth fields");
        }
        let owner_auth: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
        let endorsement_auth: [u8; 32] = data[offset + 32..offset + 64].try_into().unwrap();
        let lockout_auth: [u8; 32] = data[offset + 64..offset + 96].try_into().unwrap();
        let mut offset = offset + 96;

        if offset + 4 > data.len() {
            return Err("buffer underrun at nv_counter");
        }
        let nv_counter = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let (nv_data, offset) = read_len_prefixed(data, offset)?;

        if offset + 32 > data.len() {
            return Err("buffer underrun at platform_auth");
        }
        let platform_auth: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
        let offset = offset + 32;

        let (extra, _offset) = read_len_prefixed(data, offset)?;

        Ok(VtpmState {
            ek_priv,
            ek_pub,
            srk_priv,
            srk_pub,
            owner_auth,
            endorsement_auth,
            lockout_auth,
            nv_data,
            nv_counter,
            platform_auth,
            extra,
        })
    }

    /// Minimum empty state for bootstrap (first boot).
    pub fn empty() -> Self {
        Self {
            ek_priv: Vec::new(),
            ek_pub: Vec::new(),
            srk_priv: Vec::new(),
            srk_pub: Vec::new(),
            owner_auth: [0u8; 32],
            endorsement_auth: [0u8; 32],
            lockout_auth: [0u8; 32],
            nv_data: Vec::new(),
            nv_counter: 0,
            platform_auth: [0u8; 32],
            extra: Vec::new(),
        }
    }
}

#[inline] // R1: avoid sret aggregate-return on (Vec<u8>, usize)
fn read_len_prefixed(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), &'static str> {
    if offset + 4 > data.len() {
        return Err("buffer underrun at length prefix");
    }
    let len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    if offset + 4 + len > data.len() {
        return Err("buffer underrun at data field");
    }
    Ok((
        data[offset + 4..offset + 4 + len].to_vec(),
        offset + 4 + len,
    ))
}

// ============================================================
// SealedBlob — On-disk Format
// ============================================================

/// The on-disk sealed blob format.
///
/// Stored on public disk; integrity protected by TPM seal and AES-GCM tag.
#[derive(Debug, Clone)]
pub struct SealedBlob {
    pub version: u16,
    pub counter: u64,
    pub pcr_policy_digest: [u8; 32],
    pub sealed_priv: Vec<u8>,
    pub sealed_pub: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub vm_id: [u8; 16],
    pub created_at: u64,
}

impl SealedBlob {
    #[inline] // R1: avoid sret aggregate-return on Vec<u8>
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);

        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.pcr_policy_digest);

        out.extend_from_slice(&(self.sealed_priv.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sealed_priv);

        out.extend_from_slice(&(self.sealed_pub.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sealed_pub);

        out.extend_from_slice(&(self.encrypted_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.encrypted_data);

        out.extend_from_slice(&self.vm_id);
        out.extend_from_slice(&self.created_at.to_le_bytes());

        out
    }

    #[inline] // R1: avoid sret aggregate-return on SealedBlob
    pub fn unpack(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 42 {
            return Err("SealedBlob too short");
        }

        let version = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let counter = u64::from_le_bytes(data[2..10].try_into().unwrap());
        let pcr_policy_digest: [u8; 32] = data[10..42].try_into().unwrap();
        let mut offset = 42;

        let priv_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let sealed_priv = data[offset..offset + priv_len].to_vec();
        offset += priv_len;

        let pub_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let sealed_pub = data[offset..offset + pub_len].to_vec();
        offset += pub_len;

        let enc_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let encrypted_data = data[offset..offset + enc_len].to_vec();
        offset += enc_len;

        let vm_id: [u8; 16] = data[offset..offset + 16].try_into().unwrap();
        offset += 16;

        let created_at = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());

        Ok(SealedBlob {
            version,
            counter,
            pcr_policy_digest,
            sealed_priv,
            sealed_pub,
            encrypted_data,
            vm_id,
            created_at,
        })
    }
}

// ============================================================
// AES-256-GCM Helpers
// ============================================================

/// Encrypt plaintext with AES-256-GCM using caller-provided key material.
///
/// The caller is responsible for generating `aes_key` (32 bytes) and
/// `nonce` (12 bytes) from a cryptographically secure RNG.
/// In production: rdseed instruction via cocoon-tpm-crypto.
/// In prototype: OsRng from rand crate.
///
/// Returns (ciphertext, tag) where the GCM authentication tag is 16 bytes.
#[inline] // R1: avoid sret aggregate-return on (Vec<u8>, [u8; 16])
pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    aes_key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(Vec<u8>, [u8; 16]), SvsmReqError> {
    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let nonce_obj = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|_| SvsmReqError::invalid_request())?;

    let ct_len = ciphertext.len() - GCM_TAG_SIZE;
    let (ct, tag_slice) = ciphertext.split_at(ct_len);
    let tag: [u8; 16] = tag_slice.try_into().unwrap();

    Ok((ct.to_vec(), tag))
}

/// Decrypt ciphertext with AES-256-GCM.
#[inline] // R1: avoid sret aggregate-return on Vec<u8>
pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    aes_key: &[u8; 32],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> Result<Vec<u8>, SvsmReqError> {
    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let nonce_obj = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);

    let mut combined = Vec::with_capacity(ciphertext.len() + GCM_TAG_SIZE);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    cipher
        .decrypt(nonce_obj, combined.as_slice())
        .map_err(|_| SvsmReqError::invalid_request())
}

// ============================================================
// Seal/Unseal Orchestration
// ============================================================

/// Seal vTPM state to a SealedBlob.
///
/// Flow:
///   1. Serialize VtpmState
///   2. AES-256-GCM encrypt serialized state (key/nonce from caller)
///   3. TPM seal the 60-byte (key+tag+nonce) payload
///   4. Pack everything into SealedBlob
#[inline] // R1: avoid sret aggregate-return on SealedBlob
pub fn seal_state<T: TpmTransport>(
    proxy: &mut TpmProxy<T>,
    state: &VtpmState,
    vm_id: [u8; 16],
    aes_key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<SealedBlob, SvsmReqError> {
    let serialized = state.serialize();

    // Step 1: AES-256-GCM encrypt
    let (ciphertext, tag) = aes_gcm_encrypt(&serialized, aes_key, nonce)?;

    // Step 2: Assemble seal payload: key(32) + tag(16) + nonce(12) = 60 bytes
    let mut seal_payload = Vec::with_capacity(SEAL_PAYLOAD_SIZE);
    seal_payload.extend_from_slice(aes_key);
    seal_payload.extend_from_slice(&tag);
    seal_payload.extend_from_slice(nonce);

    // Step 3: TPM seal the 60-byte payload
    let (sealed_priv, sealed_pub) = proxy.seal_payload(&seal_payload)?;

    // Step 4: Pack into SealedBlob
    let counter = proxy.seal_counter();
    let created_at = monotonic_timestamp();

    Ok(SealedBlob {
        version: BLOB_VERSION,
        counter,
        pcr_policy_digest: [0u8; 32], // placeholder; production: derive from PCR policy
        sealed_priv,
        sealed_pub,
        encrypted_data: ciphertext,
        vm_id,
        created_at,
    })
}

/// Unseal a SealedBlob to recover vTPM state.
///
/// Flow:
///   1. TPM unseal the 60-byte payload → recover (aes_key, tag, nonce)
///   2. AES-256-GCM decrypt the encrypted data
///   3. Deserialize VtpmState
#[inline] // R1: avoid sret aggregate-return on VtpmState
pub fn unseal_state<T: TpmTransport>(
    proxy: &mut TpmProxy<T>,
    blob: &SealedBlob,
) -> Result<VtpmState, SvsmReqError> {
    // Step 1: TPM unseal
    let seal_payload = proxy.unseal_payload(&blob.sealed_priv, &blob.sealed_pub)?;

    if seal_payload.len() < SEAL_PAYLOAD_SIZE {
        log::error!(
            "Unsealed payload too short: {} bytes (expected {})",
            seal_payload.len(),
            SEAL_PAYLOAD_SIZE
        );
        return Err(SvsmReqError::invalid_request());
    }

    // Step 2: Extract AES key, tag, nonce
    let aes_key: [u8; 32] = seal_payload[0..32].try_into().unwrap();
    let tag: [u8; 16] = seal_payload[32..48].try_into().unwrap();
    let nonce: [u8; 12] = seal_payload[48..60].try_into().unwrap();

    // Step 3: AES-256-GCM decrypt
    let plaintext = aes_gcm_decrypt(&blob.encrypted_data, &aes_key, &nonce, &tag)?;

    // Step 4: Deserialize
    VtpmState::deserialize(&plaintext).map_err(|e| {
        log::error!("VtpmState deserialization failed: {e}");
        SvsmReqError::invalid_request()
    })
}

/// Compute SHA-256 hash of VtpmState serialization (for integrity check).
pub fn state_hash(state: &VtpmState) -> [u8; 32] {
    Sha256::digest(state.serialize()).into()
}

// ============================================================
// Utility
// ============================================================

/// Monotonic timestamp. In production, read from SEV-SNP attestation clock.
/// Here: simple incrementing counter (single-threaded VMPL0 context).
fn monotonic_timestamp() -> u64 {
    static mut COUNTER: u64 = 0;
    // SAFETY: VMPL0 is strictly single-threaded at initialization, so the
    // mutable static is accessed without races.
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> VtpmState {
        VtpmState {
            ek_priv: b"ek-private-bytes".to_vec(),
            ek_pub: b"ek-public-bytes-xx".to_vec(),
            srk_priv: b"srk-private".to_vec(),
            srk_pub: b"srk-public".to_vec(),
            owner_auth: [0x11u8; 32],
            endorsement_auth: [0x22u8; 32],
            lockout_auth: [0x33u8; 32],
            nv_data: b"nv-blob-contents".to_vec(),
            nv_counter: 0xDEAD_BEEF,
            platform_auth: [0x44u8; 32],
            extra: b"opaque-tail".to_vec(),
        }
    }

    fn assert_state_eq(a: &VtpmState, b: &VtpmState) {
        assert_eq!(a.ek_priv, b.ek_priv);
        assert_eq!(a.ek_pub, b.ek_pub);
        assert_eq!(a.srk_priv, b.srk_priv);
        assert_eq!(a.srk_pub, b.srk_pub);
        assert_eq!(a.owner_auth, b.owner_auth);
        assert_eq!(a.endorsement_auth, b.endorsement_auth);
        assert_eq!(a.lockout_auth, b.lockout_auth);
        assert_eq!(a.nv_data, b.nv_data);
        assert_eq!(a.nv_counter, b.nv_counter);
        assert_eq!(a.platform_auth, b.platform_auth);
        assert_eq!(a.extra, b.extra);
    }

    #[test]
    fn vtpmstate_serialize_roundtrip_full() {
        let s = sample_state();
        let bytes = s.serialize();
        let parsed = VtpmState::deserialize(&bytes).expect("deserialize");
        assert_state_eq(&s, &parsed);
    }

    #[test]
    fn vtpmstate_serialize_roundtrip_empty() {
        let s = VtpmState::empty();
        let bytes = s.serialize();
        let parsed = VtpmState::deserialize(&bytes).expect("deserialize empty");
        assert_state_eq(&s, &parsed);
        assert_eq!(parsed.nv_counter, 0);
        assert!(parsed.ek_priv.is_empty());
        assert!(parsed.extra.is_empty());
    }

    #[test]
    fn vtpmstate_deserialize_rejects_truncated() {
        let bytes = sample_state().serialize();
        // Truncate just before the trailing extra field's length prefix.
        let cut = bytes.len() - 8;
        let err = VtpmState::deserialize(&bytes[..cut]);
        assert!(err.is_err(), "expected truncation error, got {err:?}");
    }

    #[test]
    fn vtpmstate_deserialize_rejects_oversized_length() {
        // First field is ek_priv with a u32 LE length prefix. Forge a length
        // that exceeds the remaining buffer.
        let mut bytes = alloc::vec![0u8; 8];
        bytes[..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let err = VtpmState::deserialize(&bytes);
        assert!(err.is_err(), "expected oversize error, got {err:?}");
    }

    #[test]
    fn sealed_blob_pack_unpack_roundtrip() {
        let blob = SealedBlob {
            version: BLOB_VERSION,
            counter: 0x0102_0304_0506_0708,
            pcr_policy_digest: [0xAAu8; 32],
            sealed_priv: b"priv-area".to_vec(),
            sealed_pub: b"pub-area-bytes".to_vec(),
            encrypted_data: b"ciphertext-tail".to_vec(),
            vm_id: [0xBBu8; 16],
            created_at: 0x9988_7766_5544_3322,
        };
        let packed = blob.pack();
        let parsed = SealedBlob::unpack(&packed).expect("unpack");
        assert_eq!(parsed.version, blob.version);
        assert_eq!(parsed.counter, blob.counter);
        assert_eq!(parsed.pcr_policy_digest, blob.pcr_policy_digest);
        assert_eq!(parsed.sealed_priv, blob.sealed_priv);
        assert_eq!(parsed.sealed_pub, blob.sealed_pub);
        assert_eq!(parsed.encrypted_data, blob.encrypted_data);
        assert_eq!(parsed.vm_id, blob.vm_id);
        assert_eq!(parsed.created_at, blob.created_at);
    }

    #[test]
    fn sealed_blob_unpack_rejects_too_short() {
        let err = SealedBlob::unpack(&[0u8; 10]);
        assert!(err.is_err(), "expected too-short error, got {err:?}");
    }

    #[test]
    fn sealed_blob_unpack_preserves_empty_fields() {
        let blob = SealedBlob {
            version: BLOB_VERSION,
            counter: 0,
            pcr_policy_digest: [0u8; 32],
            sealed_priv: Vec::new(),
            sealed_pub: Vec::new(),
            encrypted_data: Vec::new(),
            vm_id: [0u8; 16],
            created_at: 0,
        };
        let parsed = SealedBlob::unpack(&blob.pack()).expect("unpack empty");
        assert!(parsed.sealed_priv.is_empty());
        assert!(parsed.sealed_pub.is_empty());
        assert!(parsed.encrypted_data.is_empty());
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = [0x5Au8; 32];
        let nonce = [0xA5u8; 12];
        let plaintext = b"the quick brown fox jumps over 13 lazy dogs ----------";

        let (ct, tag) = aes_gcm_encrypt(plaintext, &key, &nonce).expect("encrypt");
        assert_eq!(ct.len(), plaintext.len());

        let recovered = aes_gcm_decrypt(&ct, &key, &nonce, &tag).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aes_gcm_detects_ciphertext_tamper() {
        let key = [0x5Au8; 32];
        let nonce = [0xA5u8; 12];
        let plaintext = b"sensitive vtpm key bundle bytes ......";

        let (mut ct, tag) = aes_gcm_encrypt(plaintext, &key, &nonce).expect("encrypt");
        // Flip a bit in the ciphertext; GCM tag check must reject.
        ct[0] ^= 0x01;
        let err = aes_gcm_decrypt(&ct, &key, &nonce, &tag);
        assert!(err.is_err(), "tampered ciphertext must fail decrypt");
    }

    #[test]
    fn aes_gcm_detects_tag_tamper() {
        let key = [0x5Au8; 32];
        let nonce = [0xA5u8; 12];
        let plaintext = b"sensitive vtpm key bundle bytes ......";

        let (ct, mut tag) = aes_gcm_encrypt(plaintext, &key, &nonce).expect("encrypt");
        tag[0] ^= 0x80;
        let err = aes_gcm_decrypt(&ct, &key, &nonce, &tag);
        assert!(err.is_err(), "tampered tag must fail decrypt");
    }

    #[test]
    fn aes_gcm_detects_wrong_key() {
        let key = [0x5Au8; 32];
        let mut wrong = key;
        wrong[31] ^= 0xFF;
        let nonce = [0xA5u8; 12];
        let plaintext = b"sensitive vtpm key bundle bytes ......";

        let (ct, tag) = aes_gcm_encrypt(plaintext, &key, &nonce).expect("encrypt");
        let err = aes_gcm_decrypt(&ct, &wrong, &nonce, &tag);
        assert!(err.is_err(), "wrong key must fail decrypt");
    }

    #[test]
    fn state_hash_stable_and_sensitive() {
        let s1 = sample_state();
        let mut s2 = s1.clone();
        let h1 = state_hash(&s1);
        let h1b = state_hash(&s1);
        assert_eq!(h1, h1b, "hash must be deterministic");

        s2.nv_counter ^= 1;
        let h2 = state_hash(&s2);
        assert_ne!(h1, h2, "hash must change on field flip");
    }
}
