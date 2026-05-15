// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate defines the Virtual TPM interfaces and shows what
//! TPM backends are supported

/// TPM 2.0 command construction over a pluggable transport (used to proxy
/// commands to a TPM endpoint outside the CVM).
pub mod proxy;
/// Two-layer container (AES-256-GCM + TPM2_Seal of a key bundle) for
/// persisting vTPM state across cold boots.
pub mod sealed;
/// Pluggable storage backend for the sealed vTPM blob.
pub mod sealed_store;
/// TPM internal-state extraction and injection via libtcgtpm accessors.
pub mod state;
/// TPM 2.0 Reference Implementation
pub mod tcgtpm;

extern crate alloc;

use alloc::vec::Vec;

use crate::vtpm::tcgtpm::TcgTpm as Vtpm;
use crate::{locking::LockGuard, protocols::vtpm::TpmPlatformCommand};
use crate::{locking::SpinLock, protocols::errors::SvsmReqError};

/// Basic services required to perform the VTPM Protocol
pub trait VtpmProtocolInterface {
    /// Get the list of Platform Commands supported by the TPM implementation.
    fn get_supported_commands(&self) -> &[TpmPlatformCommand];
}

/// This implements one handler for each [`TpmPlatformCommand`] supported by the
/// VTPM Protocol. These handlers are based on the TPM Simulator interface
/// provided by the TPM 2.0 Reference Implementation, but with a few changes
/// to make it more Rust idiomatic.
///
/// `tpm-20-ref/TPMCmd/Simulator/include/prototypes/Simulator_fp.h`
pub trait TcgTpmSimulatorInterface: VtpmProtocolInterface {
    /// Send a command for the TPM to run in a given locality
    ///
    /// # Arguments
    ///
    /// * `command`: Buffer with the command to be sent to the TPM.
    /// * `locality`: TPM locality the TPM command will be executed
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the response received from the TPM on success,
    /// or an error.
    fn send_tpm_command(&self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError>;

    /// Power-on the TPM, which also triggers a reset
    ///
    /// # Arguments
    ///
    /// *`only_reset``: If enabled, it will only reset the vTPM;
    ///                 however, the vtPM has to be powered on previously.
    ///                 Otherwise, it will fail.
    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError>;

    /// In a system where the NV memory used by the TPM is not within the TPM,
    /// the NV may not always be available. This function indicates that NV
    /// is available.
    fn signal_nvon(&self) -> Result<(), SvsmReqError>;
}

#[derive(Debug)]
pub enum SvsmVTpmError {
    ReqError(SvsmReqError),
    CommandError(u32),
}

impl From<SvsmReqError> for SvsmVTpmError {
    fn from(err: SvsmReqError) -> Self {
        SvsmVTpmError::ReqError(err)
    }
}

impl From<SvsmVTpmError> for SvsmReqError {
    fn from(err: SvsmVTpmError) -> Self {
        match err {
            SvsmVTpmError::ReqError(e) => e,
            SvsmVTpmError::CommandError(_) => SvsmReqError::invalid_request(),
        }
    }
}

/// Basic TPM driver services
pub trait VtpmInterface: TcgTpmSimulatorInterface {
    /// Check if the TPM is powered on.
    fn is_powered_on(&self) -> bool;

    /// Prepare the TPM to be used for the first time. At this stage,
    /// the TPM is manufactured.
    fn init(&mut self) -> Result<(), SvsmReqError>;

    /// Returns the cached EK public key if it exists, otherwise it returns an error indicating
    /// that the EK public key does not exist.
    /// Needs mutability to cache the key.
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError>;
}

/// vTPM boot mode driving the persistence cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtpmBootMode {
    /// First boot: manufacture vTPM, extract internal state, seal to the
    /// external TPM, return the sealed blob for host-side storage.
    Provision,
    /// Subsequent boot: unseal the sealed blob, inject state, light power-on.
    Recover,
}

/// VSOCK addressing for the host-side TPM endpoint.
pub const VSOCK_HOST_CID: u32 = 2;
pub const VSOCK_TPM_PORT: u32 = 9999;

static VTPM: SpinLock<Vtpm> = SpinLock::new(Vtpm::new());

/// Initialize the TPM by calling the init() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_init() -> Result<(), SvsmReqError> {
    let mut vtpm = VTPM.lock();
    if vtpm.is_powered_on() {
        return Ok(());
    }
    vtpm.init()?;
    Ok(())
}

/// vTPM initialization with seal/unseal integration.
///
/// Provision mode: manufacture vTPM, extract internal state, AES-256-GCM
/// encrypt, TPM2_Seal the key bundle, return the packed SealedBlob bytes.
/// Recover mode: unpack the SealedBlob, TPM2_Unseal the key bundle, AES
/// decrypt, inject internal state, perform a light power-on.
pub fn vtpm_init_sealed<T: TpmTransport>(
    transport: T,
    mode: VtpmBootMode,
    vm_id: [u8; 16],
    sealed_blob_data: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, SvsmReqError> {
    let mut vtpm = VTPM.lock();
    if vtpm.is_powered_on() {
        return Ok(None);
    }

    let mut proxy = TpmProxy::new(transport);

    match mode {
        VtpmBootMode::Provision => {
            vtpm.init()?;
            log::info!("VTPM: manufactured (Provision mode)");

            // Bulk-serialize the TPM internal state (seeds, PCR save area,
            // auth values, counters) into an opaque byte buffer. This is
            // round-tripped via inject_serialized_state() on Recover.
            let serialized = state::extract_serialized_state()?;
            log::info!(
                "VTPM: internal state extracted ({} bytes)",
                serialized.len()
            );

            let vtpm_state = VtpmState {
                ek_priv: Vec::new(),
                ek_pub: vtpm.get_ekpub()?,
                srk_priv: Vec::new(),
                srk_pub: Vec::new(),
                owner_auth: [0u8; 32],
                endorsement_auth: [0u8; 32],
                lockout_auth: [0u8; 32],
                nv_data: Vec::new(),
                nv_counter: 0,
                platform_auth: [0u8; 32],
                extra: serialized,
            };

            let (aes_key, nonce) = platform_entropy()?;
            let blob = sealed::seal_state(&mut proxy, &vtpm_state, vm_id, &aes_key, &nonce)
                .map_err(|_| SvsmReqError::invalid_request())?;
            zeroize_key_material(&aes_key, &nonce);

            log::info!(
                "VTPM: state sealed to TPM (counter={}, enc_size={})",
                blob.counter,
                blob.encrypted_data.len()
            );

            proxy.flush_primary();
            Ok(Some(blob.pack()))
        }

        VtpmBootMode::Recover => {
            let blob_data = sealed_blob_data.ok_or_else(|| {
                log::error!("VTPM: Recover mode requires sealed_blob_data");
                SvsmReqError::invalid_request()
            })?;

            let blob = SealedBlob::unpack(blob_data).map_err(|_| {
                log::error!("VTPM: failed to unpack SealedBlob");
                SvsmReqError::invalid_request()
            })?;

            log::info!("VTPM: SealedBlob loaded (counter={})", blob.counter);

            let vtpm_state = sealed::unseal_state(&mut proxy, &blob).map_err(|_| {
                log::error!("VTPM: unseal_state failed");
                SvsmReqError::invalid_request()
            })?;

            proxy.flush_primary();

            // Inject the serialized internal state back into the TPM via the
            // C-side bulk deserializer.
            state::inject_serialized_state(&vtpm_state.extra).map_err(|_| {
                log::error!("VTPM: inject_serialized_state failed");
                SvsmReqError::invalid_request()
            })?;

            log::info!("VTPM: internal state injected");

            vtpm.signal_poweron(false)?;
            vtpm.signal_nvon()?;

            log::info!(
                "VTPM: state recovered from TPM seal (counter={})",
                blob.counter
            );

            Ok(None)
        }
    }
}

/// Generate an AES-256 key and a GCM nonce from the platform entropy source
/// (RDSEED).
fn platform_entropy() -> Result<([u8; 32], [u8; 12]), SvsmReqError> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];

    // SAFETY: `_rdseed64_step` is a CPU intrinsic with no memory side-effects
    // beyond the pointed-to u64; pointers come from properly aligned slices.
    unsafe {
        for i in 0..4 {
            let mut retries = 0;
            loop {
                if core::arch::x86_64::_rdseed64_step(
                    &mut *(key[i * 8..][..8].as_mut_ptr() as *mut u64),
                ) == 1
                {
                    break;
                }
                retries += 1;
                if retries > 100 {
                    return Err(SvsmReqError::invalid_request());
                }
                core::arch::x86_64::_mm_pause();
            }
        }
        let mut retries = 0;
        loop {
            if core::arch::x86_64::_rdseed64_step(&mut *(nonce[..8].as_mut_ptr() as *mut u64)) == 1
            {
                break;
            }
            retries += 1;
            if retries > 100 {
                return Err(SvsmReqError::invalid_request());
            }
            core::arch::x86_64::_mm_pause();
        }
        let mut retries = 0;
        loop {
            if core::arch::x86_64::_rdseed64_step(&mut *(nonce[8..].as_mut_ptr() as *mut u64)) == 1
            {
                break;
            }
            retries += 1;
            if retries > 100 {
                return Err(SvsmReqError::invalid_request());
            }
            core::arch::x86_64::_mm_pause();
        }
    }

    Ok((key, nonce))
}

/// Zeroize key material in-place using volatile writes.
fn zeroize_key_material(aes_key: &[u8; 32], nonce: &[u8; 12]) {
    // SAFETY: volatile writes into stack-owned arrays whose lifetimes are
    // still live; pointers are valid for `write_volatile` and within bounds.
    unsafe {
        let key_ptr = aes_key.as_ptr() as *mut u8;
        for i in 0..32 {
            key_ptr.add(i).write_volatile(0);
        }
        let nonce_ptr = nonce.as_ptr() as *mut u8;
        for i in 0..12 {
            nonce_ptr.add(i).write_volatile(0);
        }
    }
}

pub fn vtpm_get_locked<'a>() -> LockGuard<'a, Vtpm> {
    VTPM.lock()
}

/// Get the TPM manifest i.e the EK public key by calling the get_ekpub() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_get_manifest() -> Result<Vec<u8>, SvsmReqError> {
    let mut vtpm = VTPM.lock();
    vtpm.get_ekpub()
}

// Re-export sealed/proxy/state types for use by kernel init (svsm.rs)
#[cfg(feature = "vsock")]
pub use proxy::VsockTransport;
pub use proxy::{MockTransport, TpmProxy, TpmTransport};
pub use sealed::{SealedBlob, VtpmState};
#[cfg(feature = "vsock")]
pub use sealed_store::VsockHostStore;
pub use sealed_store::{IgvmVarStore, SealedBlobStore, StaticBufStore};
pub use state::VtpmInternalState;
