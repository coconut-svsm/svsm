// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! SVSM Random Number Generator (RNG) management.
//!
//! Whenever users need an cryptographically secure RNG, they should invoke [`get_svsm_rng()`] to
//! obtain an exclusively owned [`SvsmRng`] instance.

extern crate alloc;
use alloc::boxed::Box;

use crate::utils::pool::{Pool, PoolGuard};

use cocoon_tpm_crypto::{CryptoError, rng};

mod drbg;
use drbg::SvsmRngImpl;

/// Number of [`SVSM_RNG_POOL`] slots.
const SVSM_RNG_POOL_SIZE: usize = 4;

/// RNG instance pool
///
/// Dropped [`SvsmRng`] instances return to the pool for reuse. [`get_svsm_rng()`] takes from
/// the pool when possible, falling back to instantiation.
static SVSM_RNG_POOL: Pool<Box<SvsmRngImpl>, SVSM_RNG_POOL_SIZE> = Pool::empty();

/// Opaque type implementing [`rng::RngCore`] as suitable for the SVSM environment and build
/// configuration.
///
/// Instances of `SvsmRng` are to be obtained through [`get_svsm_rng()`].
///
/// No assumptions must be made about `SvsmRng`, other than instances thereof are small, typically
/// of pointer size, and that it implements [`rng::RngCore`].
#[allow(missing_debug_implementations)]
pub struct SvsmRng {
    guard: PoolGuard<'static, Box<SvsmRngImpl>, SVSM_RNG_POOL_SIZE>,
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
        self.guard.generate(output, additional_input)
    }
}

/// Obtain an exclusively owned [`SvsmRng`] instance.
pub fn get_svsm_rng() -> Result<SvsmRng, CryptoError> {
    let guard = SVSM_RNG_POOL.get(SvsmRngImpl::new)?;
    Ok(SvsmRng { guard })
}
