// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! SVSM kernel crypto API

pub mod aead {
    //! API for authentication encryption with associated data

    use crate::{protocols::errors::SvsmReqError, sev::secrets_page::VMPCK_SIZE};

    // Message Header Format (AMD SEV-SNP spec. table 98)

    /// Authenticated tag size (128 bits)
    pub const AUTHTAG_SIZE: usize = 16;
    /// Initialization vector size (96 bits)
    pub const IV_SIZE: usize = 12;
    /// Key size
    pub const KEY_SIZE: usize = VMPCK_SIZE;

    /// AES-256 GCM
    pub trait Aes256GcmTrait {
        /// Encrypt the provided buffer using AES-256 GCM
        ///
        /// # Arguments
        ///
        /// * `iv`: Initialization vector
        /// * `key`: 256-bit key
        /// * `aad`: Additional authenticated data
        /// * `inbuf`: Cleartext buffer to be encrypted
        /// * `outbuf`: Buffer to store the encrypted data, it must be large enough to also
        ///   hold the authenticated tag.
        ///
        /// # Returns
        ///
        /// * Success
        ///     * `usize`: Number of bytes written to `outbuf`
        /// * Error
        ///     * [SvsmReqError]
        fn encrypt(
            iv: &[u8; IV_SIZE],
            key: &[u8; KEY_SIZE],
            aad: &[u8],
            inbuf: &[u8],
            outbuf: &mut [u8],
        ) -> Result<usize, SvsmReqError>;

        /// Decrypt the provided buffer using AES-256 GCM
        ///
        /// # Returns
        ///
        /// * `iv`: Initialization vector
        /// * `key`: 256-bit key
        /// * `aad`: Additional authenticated data
        /// * `inbuf`: Cleartext buffer to be decrypted, followed by the authenticated tag
        /// * `outbuf`: Buffer to store the decrypted data
        ///
        /// # Returns
        ///
        /// * Success
        ///     * `usize`: Number of bytes written to `outbuf`
        /// * Error
        ///     * [SvsmReqError]
        fn decrypt(
            iv: &[u8; IV_SIZE],
            key: &[u8; KEY_SIZE],
            aad: &[u8],
            inbuf: &[u8],
            outbuf: &mut [u8],
        ) -> Result<usize, SvsmReqError>;
    }

    /// Aes256Gcm type
    #[derive(Copy, Clone, Debug)]
    pub struct Aes256Gcm;
}

pub mod digest {
    //! API for message digests.

    extern crate alloc;

    use alloc::vec::Vec;

    // Note the typical new/update/finish API is not initially supported due
    // to our inability to hide an abstract implementation's state representation
    // behind a type without any fields.

    pub trait Algorithm {
        /// Digests `input` into an output vector of size `OUTPUT_LEN`.
        fn digest(input: &[u8]) -> Vec<u8>;
    }

    /// Sha512 type
    #[derive(Copy, Clone, Debug)]
    pub struct Sha512;
}

// Crypto implementations supported. Only one of them must be compiled-in.

pub mod rustcrypto;
