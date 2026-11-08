// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

extern crate alloc;
use alloc::boxed::Box;

use cocoon_tpm_crypto::{
    CryptoError, CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter,
    rng::{self, OsslRandBytesRng, RngGenerateError},
};
use cocoon_tpm_utils_common::alloc::box_try_new;

/// OpenSSL-backed RNG wrapping `RAND_bytes()`.
pub(super) struct SvsmRngImpl {
    inner: OsslRandBytesRng,
}

impl SvsmRngImpl {
    pub(super) fn new() -> Result<Box<Self>, CryptoError> {
        box_try_new(SvsmRngImpl {
            inner: OsslRandBytesRng::new(),
        })
        .map_err(|_| CryptoError::MemoryAllocationFailure)
    }
}

impl rng::RngCore for SvsmRngImpl {
    fn generate<
        'a,
        'b,
        OI: CryptoWalkableIoSlicesMutIter<'a>,
        AII: CryptoPeekableIoSlicesIter<'b>,
    >(
        &mut self,
        output: OI,
        additional_input: Option<AII>,
    ) -> Result<(), RngGenerateError> {
        self.inner.generate(output, additional_input)
    }
}
