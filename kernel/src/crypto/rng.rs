// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! SVSM Random Number Generator (RNG) management.
//!
//! Whenever users need an cryptographically secure RNG, they should invoke [`get_svsm_rng()`] to
//! obtain an exclusively owned [`SvsmRng`] instance.

extern crate alloc;
use alloc::boxed::Box;

use crate::locking::SpinLock;

use core::sync::atomic;

use cocoon_tpm_crypto::{
    rng::{self, HashDrbg, RngCore, X86RdSeedRng},
    CryptoError, EmptyCryptoIoSlices,
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

/// RNG instance pool
///
/// [`SvsmRng::drop()`] returns instances back into some free slot, if any. [`get_svsm_rng()`] tries
/// to take a currently unused instance from the pool before attempting to instantiate one.
#[allow(clippy::type_complexity)]
static SVSM_RNG_POOL: SpinLock<
    [Option<Box<rng::ChainedRng<rng::X86RdSeedRng, rng::HashDrbg>>>; 4],
> = SpinLock::new([None, None, None, None]);

/// Counter used for the RNG instance's personalization.
static SVSM_RNG_INSTANTIATION_ID: atomic::AtomicU64 = atomic::AtomicU64::new(0);

/// Opaque type implementing [`RngCore`] as suitable for the SVSM environment and build
/// configuration.
///
/// Instances of `SvsmRng` are to be obtained through [`get_svsm_rng()`].
///
/// No assumptions must be made about `SvsmRng`, other than instances thereof are small, typically
/// of pointer size), and that it implements [`RngCore`].
#[allow(missing_debug_implementations)]
pub struct SvsmRng {
    // Is never None while self is alive, the rng needs to get stored in an Option<> so that it can
    // get returned back to the pool when dropped.
    rng: Option<Box<rng::ChainedRng<X86RdSeedRng, rng::HashDrbg>>>,
}

impl SvsmRng {
    fn instantiate() -> Result<Self, CryptoError> {
        let mut hash_drbg_entropy = zeroize::Zeroizing::new(
            FixedVec::<u8, 5>::new_with_default(HashDrbg::min_seed_entropy_len(
                SVSM_RNG_DRBG_HASH_ALG,
            ))
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

        let chained_rng = rng::ChainedRng::chain(rdseed_rng, hash_drbg_rng);

        Ok(Self {
            rng: Some(box_try_new(chained_rng).map_err(|_| CryptoError::MemoryAllocationFailure)?),
        })
    }
}

impl rng::RngCore for SvsmRng {
    fn generate<
        'a,
        'b,
        OI: cocoon_tpm_crypto::CryptoWalkableIoSlicesMutIter<'a>,
        AII: cocoon_tpm_crypto::CryptoPeekableIoSlicesIter<'b>,
    >(
        &mut self,
        output: OI,
        additional_input: Option<AII>,
    ) -> Result<(), rng::RngGenerateError> {
        let rng = match self.rng.as_mut() {
            Some(rng) => rng,
            None => {
                return Err(rng::RngGenerateError::CryptoError(CryptoError::Internal));
            }
        };
        rng.generate(output, additional_input)
    }
}

impl Drop for SvsmRng {
    fn drop(&mut self) {
        if let Some(rng) = self.rng.take() {
            // Return the rng instance in some free pool slot, if any.
            let mut pool = SVSM_RNG_POOL.lock();
            for pool_slot in pool.iter_mut() {
                if pool_slot.is_none() {
                    *pool_slot = Some(rng);
                    break;
                }
            }
        }
    }
}

/// Obtain an exclusively owned [`SvsmRng`] instance.
pub fn get_svsm_rng() -> Result<SvsmRng, CryptoError> {
    let mut pool = SVSM_RNG_POOL.lock();
    for pool_slot in pool.iter_mut() {
        if let Some(rng) = pool_slot.take() {
            return Ok(SvsmRng { rng: Some(rng) });
        }
    }

    SvsmRng::instantiate()
}
