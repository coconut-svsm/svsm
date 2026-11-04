// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::boxed::Box;

use core::sync::atomic;

use cocoon_tpm_crypto::{
    CryptoError, CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter, EmptyCryptoIoSlices,
    hash::hash_alg_digest_len,
    rng::{self, HashDrbg, RngCore as _, RngGenerateError, X86RdSeedRng},
};
use cocoon_tpm_tpm2_interface::TpmiAlgHash;
use cocoon_tpm_utils_common::{
    alloc::box_try_new,
    fixed_vec::{FixedVec, FixedVecMemoryAllocationFailure},
    io_slices::{self, IoSlicesIterCommon as _},
    zeroize,
};

/// Hash algorithm to be used for all NIST HashDrbg instantiations.
// C.f. NIST SP 800-90A Rev. 1: the HashDrbg's security strength is equal to the underlying hash
// algorithm's pre-image resistance. That is, SHA256 gives a security strength of 256 bits.
const SVSM_RNG_DRBG_HASH_ALG: TpmiAlgHash = TpmiAlgHash::Sha256;

/// Counter used for the RNG instance's personalization.
static SVSM_RNG_INSTANTIATION_ID: atomic::AtomicU64 = atomic::AtomicU64::new(0);

/// DRBG-based RNG seeded from hardware entropy (RDSEED).
pub(super) struct SvsmRngImpl {
    inner: rng::ChainedRng<X86RdSeedRng, HashDrbg>,
}

impl SvsmRngImpl {
    pub(super) fn new() -> Result<Box<Self>, CryptoError> {
        // The FixedVec internal representation is optimized for the case of power-of-two lengths,
        // relative to a specified compile-time "base" value. In practice, the HashDrbg seed length
        // is equal to the digest length for all known hashes, so use that for the FixedVec base. If
        // not a power of two (e.g. SHA-1), the optimization wouldn't be possible anyway, so the
        // value is irrelevant then.
        const DRBG_HASH_ALG_DIGEST_LEN_LOG2: u32 =
            hash_alg_digest_len(SVSM_RNG_DRBG_HASH_ALG).ilog2();
        let mut hash_drbg_entropy = zeroize::Zeroizing::new(
            FixedVec::<u8, DRBG_HASH_ALG_DIGEST_LEN_LOG2>::new_with_default(
                HashDrbg::min_seed_entropy_len(SVSM_RNG_DRBG_HASH_ALG),
            )
            .map_err(|e| match e {
                FixedVecMemoryAllocationFailure => CryptoError::MemoryAllocationFailure,
            })?,
        );

        let mut rdseed_rng = X86RdSeedRng::instantiate().map_err(|_| CryptoError::RngFailure)?;
        rdseed_rng.generate::<_, EmptyCryptoIoSlices>(
            io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice())
                .map_infallible_err(),
            None,
        )?;

        let mut personalization = [0u8; 16];
        personalization[..8].copy_from_slice(b"SVSM-RNG");
        personalization[8..].copy_from_slice(
            &SVSM_RNG_INSTANTIATION_ID
                .fetch_add(1, atomic::Ordering::Relaxed)
                .to_ne_bytes(),
        );

        let hash_drbg_rng = rng::HashDrbg::instantiate(
            SVSM_RNG_DRBG_HASH_ALG,
            &hash_drbg_entropy,
            None,
            Some(&personalization),
        )?;

        let inner = rng::ChainedRng::chain(rdseed_rng, hash_drbg_rng);
        box_try_new(SvsmRngImpl { inner }).map_err(|_| CryptoError::MemoryAllocationFailure)
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
