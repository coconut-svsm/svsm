// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! RustCrypto implementation

extern crate alloc;

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use alloc::{vec, vec::Vec};
use cocoon_tpm_crypto::hash::{HashInstance, hash_alg_digest_len};
use cocoon_tpm_tpm2_interface::TpmiAlgHash;
use cocoon_tpm_utils_common::io_slices::{IoSlicesIterCommon as _, SingletonIoSlice};

use crate::error::SvsmError;
use crate::{
    crypto::aead::{
        Aes256Gcm as CryptoAes256Gcm, Aes256GcmTrait as CryptoAes256GcmTrait, IV_SIZE, KEY_SIZE,
    },
    crypto::digest::{Algorithm as CryptoHashTrait, Sha512 as CryptoSha512},
};

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum AesGcmOperation {
    Encrypt = 0,
    Decrypt = 1,
}

fn aes_gcm_do(
    operation: AesGcmOperation,
    iv: &[u8; IV_SIZE],
    key: &[u8; KEY_SIZE],
    aad: &[u8],
    inbuf: &[u8],
    outbuf: &mut [u8],
) -> Result<usize, SvsmError> {
    let payload = Payload { msg: inbuf, aad };

    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let gcm = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(iv);

    let result = if operation == AesGcmOperation::Encrypt {
        gcm.encrypt(nonce, payload)
    } else {
        gcm.decrypt(nonce, payload)
    };
    let buffer = result.map_err(|_| SvsmError::InvalidFormat)?;

    let outbuf = outbuf
        .get_mut(..buffer.len())
        .ok_or(SvsmError::InvalidParameter)?;
    outbuf.copy_from_slice(&buffer);

    Ok(buffer.len())
}

impl CryptoAes256GcmTrait for CryptoAes256Gcm {
    fn encrypt(
        iv: &[u8; IV_SIZE],
        key: &[u8; KEY_SIZE],
        aad: &[u8],
        inbuf: &[u8],
        outbuf: &mut [u8],
    ) -> Result<usize, SvsmError> {
        aes_gcm_do(AesGcmOperation::Encrypt, iv, key, aad, inbuf, outbuf)
    }

    fn decrypt(
        iv: &[u8; IV_SIZE],
        key: &[u8; KEY_SIZE],
        aad: &[u8],
        inbuf: &[u8],
        outbuf: &mut [u8],
    ) -> Result<usize, SvsmError> {
        aes_gcm_do(AesGcmOperation::Decrypt, iv, key, aad, inbuf, outbuf)
    }
}

impl CryptoHashTrait for CryptoSha512 {
    fn digest(input: &[u8]) -> Vec<u8> {
        let mut sha = HashInstance::new(TpmiAlgHash::Sha512).expect("SHA-512 not supported");
        // Hashing a single in-memory slice cannot fail.
        sha.update(SingletonIoSlice::new(input).map_infallible_err())
            .expect("SHA-512 update failed");
        let mut digest = vec![0u8; hash_alg_digest_len(TpmiAlgHash::Sha512) as usize];
        sha.finalize_into(&mut digest)
            .expect("SHA-512 finalize failed");
        digest
    }
}
