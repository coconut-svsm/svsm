// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate defines the Virtual TPM interfaces and shows what
//! TPM backends are supported.
//!
//! # ABI safety convention (post-R1)
//!
//! In `release` builds a callee-saved register (`%rbx`) was observed to
//! be corrupted across a nested sret-returning call inside
//! `vtpm_init_sealed`, producing a page-fault on the eventual MutexGuard
//! drop. Root cause was the SysV-ABI sret indirection used for any
//! `Result<T, E>` whose payload exceeds two registers (≈ 16 bytes),
//! combined with multiple long-lived values competing for callee-saved
//! registers.
//!
//! To prevent this class of defect from regressing, every function in
//! the `vtpm` subtree whose return type exceeds 16 bytes (notably
//! anything returning `Vec<u8>`, `Option<Vec<u8>>`, tuples of `Vec`s,
//! or non-trivial structs by value) is annotated `#[inline]` so LLVM
//! is encouraged to inline the call and skip the sret aggregate
//! marshalling entirely. Two hot-path functions
//! (`vtpm_init_sealed`, `platform_entropy`) additionally use the
//! explicit `&mut` out-param pattern instead of returning an
//! aggregate. New code in this module must follow the same rule.

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

/// Runtime re-seal hook triggered by guest TPM2_Shutdown.
#[cfg(feature = "vtpm-persist")]
pub mod reseal;

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

    /// Bring the TPM simulator's platform layer up *without* manufacturing.
    ///
    /// Used by the Recover boot path: the persistent seeds (EPS/SPS/PPS)
    /// are restored via [`crate::vtpm::state::inject_serialized_state`]
    /// from the sealed blob, so re-running `manufacture` here would
    /// overwrite them and silently break every key derived from those
    /// seeds (EK, SRK, IAK, ...). Implementations must still allocate
    /// NV, power the simulator on, and signal NV-available so that the
    /// subsequent inject + TPM2_Startup sequence can succeed.
    ///
    /// The default implementation is a stub that fails — only backends
    /// that actually support state injection should override it.
    fn recover_init(&mut self) -> Result<(), SvsmReqError> {
        Err(SvsmReqError::invalid_request())
    }

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
/// encrypt, TPM2_Seal the key bundle, write the packed SealedBlob bytes
/// into `out_blob`.
/// Recover mode: unpack the SealedBlob, TPM2_Unseal the key bundle, AES
/// decrypt, inject internal state, perform a light power-on. `out_blob`
/// is left untouched.
///
/// NOTE on signature shape (R1): the original signature returned
/// `Result<Option<Vec<u8>>, SvsmReqError>` (a ~32-byte aggregate) and
/// internally called `platform_entropy() -> Result<([u8; 32], [u8; 12]),
/// SvsmReqError>` (a 49-byte aggregate). Under `release` codegen both
/// aggregates went through the SysV-ABI sret indirection, and on ZEN5
/// hardware that path caused callee-saved `%rbx` to be reloaded with a
/// stale kernel-mapping pointer between prologue and the final return
/// write, producing a wild page-fault on the discriminant store. Both
/// functions were refactored to register-sized `Result<(), SvsmReqError>`
/// with `&mut` out-params so the sret path is no longer used.
pub fn vtpm_init_sealed<T: TpmTransport>(
    transport: T,
    mode: VtpmBootMode,
    vm_id: [u8; 16],
    sealed_blob_data: Option<&[u8]>,
    out_blob: &mut Option<Vec<u8>>,
) -> Result<(), SvsmReqError> {
    *out_blob = None;
    let mut vtpm = VTPM.lock();
    if vtpm.is_powered_on() {
        return Ok(());
    }

    let mut proxy = TpmProxy::new(transport);

    match mode {
        VtpmBootMode::Provision => {
            vtpm.init()?;
            log::info!("VTPM: manufactured (Provision mode)");

            // The TPM 2.0 reference impl leaves the simulator in
            // "needs TPM2_Startup" state after init() — normally OVMF would
            // issue the startup command. The sealed-init flow runs *before*
            // guest firmware boot, so we have to issue Startup(SU_CLEAR)
            // ourselves before any TPM2_CreatePrimary / TPM2_Create call.
            early_tpm_startup(&*vtpm)?;

            // Bulk-serialize the TPM internal state (seeds, PCR save area,
            // auth values, counters) into an opaque byte buffer. This is
            // round-tripped via inject_serialized_state() on Recover.
            let serialized = state::extract_serialized_state()?;
            log::info!(
                "VTPM: internal state extracted ({} bytes)",
                serialized.len()
            );

            let ek_pub = vtpm.get_ekpub()?;
            log::info!("VTPM: ek_pub fetched ({} bytes)", ek_pub.len());

            let vtpm_state = VtpmState {
                ek_priv: Vec::new(),
                ek_pub,
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

            let mut aes_key = [0u8; 32];
            let mut nonce = [0u8; 12];
            platform_entropy(&mut aes_key, &mut nonce).inspect_err(|_| {
                log::error!("VTPM: platform_entropy failed");
            })?;
            let blob = sealed::seal_state(&mut proxy, &vtpm_state, vm_id, &aes_key, &nonce)
                .map_err(|e| {
                    log::error!("VTPM: seal_state failed: {e:?}");
                    SvsmReqError::invalid_request()
                })?;
            zeroize_key_material(&aes_key, &nonce);

            log::info!(
                "VTPM: state sealed to TPM (counter={}, enc_size={})",
                blob.counter,
                blob.encrypted_data.len()
            );

            proxy.flush_primary();

            #[cfg(feature = "vtpm-persist")]
            reseal::install_reseal_context(
                vm_id,
                VSOCK_HOST_CID,
                VSOCK_TPM_PORT,
                9997, // VsockHostStore::DEFAULT_LOAD_PORT
                9998, // VsockHostStore::DEFAULT_SAVE_PORT
            );

            // R1: write through out-param (no sret aggregate) and return a
            // register-sized Result to avoid the corrupted-%rbx fault.
            *out_blob = Some(blob.pack());
            Ok(())
        }

        VtpmBootMode::Recover => {
            // Bring the in-process simulator's platform layer up without
            // manufacturing. This allocates NV, powers the simulator on
            // and signals NV-available, but does NOT touch the seeds —
            // those will be restored by inject_serialized_state below.
            vtpm.recover_init()?;
            log::info!("VTPM: platform bring-up complete (Recover mode)");

            let blob_data = sealed_blob_data.ok_or_else(|| {
                log::error!("VTPM: Recover mode requires sealed_blob_data");
                SvsmReqError::invalid_request()
            })?;

            let blob = SealedBlob::unpack(blob_data).map_err(|_| {
                log::error!("VTPM: failed to unpack SealedBlob");
                SvsmReqError::invalid_request()
            })?;

            log::info!("VTPM: SealedBlob loaded (counter={})", blob.counter);

            // Unseal the AES key bundle through the TPM proxy. This is
            // independent of the in-process simulator's globals, so it
            // can run before inject.
            let vtpm_state = sealed::unseal_state(&mut proxy, &blob).map_err(|_| {
                log::error!("VTPM: unseal_state failed");
                SvsmReqError::invalid_request()
            })?;

            proxy.flush_primary();

            // Inject the serialized internal state into the simulator's
            // globals. This must run AFTER recover_init (globals must be
            // allocated) but BEFORE early_tpm_startup so that Startup
            // sees the restored seeds and derives the hierarchies from
            // them rather than from defaults.
            state::inject_serialized_state(&vtpm_state.extra).map_err(|_| {
                log::error!("VTPM: inject_serialized_state failed");
                SvsmReqError::invalid_request()
            })?;
            log::info!("VTPM: internal state injected");

            // Now drive TPM2_Startup so the restored hierarchies come up.
            // SU_CLEAR is correct here — the seeds are recovered, so the
            // resulting EK/SRK/IAK derivations match the Provision boot.
            early_tpm_startup(&*vtpm)?;

            log::info!(
                "VTPM: state recovered from TPM seal (counter={})",
                blob.counter
            );

            #[cfg(feature = "vtpm-persist")]
            reseal::install_reseal_context(
                vm_id,
                VSOCK_HOST_CID,
                VSOCK_TPM_PORT,
                9997, // VsockHostStore::DEFAULT_LOAD_PORT
                9998, // VsockHostStore::DEFAULT_SAVE_PORT
            );

            Ok(())
        }
    }
}

/// Issue `TPM2_Startup(SU_CLEAR)` to the in-process vTPM simulator.
///
/// The TCG TPM 2.0 reference implementation leaves the simulator in a
/// post-init / pre-startup state where every command other than Startup
/// returns `TPM_RC_INITIALIZE` (0x100). In the canonical SVSM boot flow,
/// guest OVMF issues Startup once firmware boots. The sealed-init flow
/// runs strictly *before* guest firmware, so it has to issue Startup
/// itself.
fn early_tpm_startup<T: TcgTpmSimulatorInterface>(vtpm: &T) -> Result<(), SvsmReqError> {
    // TPM2_Startup(SU_CLEAR) — 12-byte fixed command:
    //   tag      = TPM_ST_NO_SESSIONS (0x8001)
    //   size     = 12
    //   cmdCode  = TPM_CC_Startup (0x00000144)
    //   startupType = TPM_SU_CLEAR (0x0000)
    const STARTUP_CMD: [u8; 12] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let response = vtpm.send_tpm_command(&STARTUP_CMD, 0).map_err(|_| {
        log::error!("VTPM: early TPM2_Startup send failed");
        SvsmReqError::invalid_request()
    })?;
    if response.len() < 10 {
        log::error!(
            "VTPM: early TPM2_Startup short response ({} bytes)",
            response.len()
        );
        return Err(SvsmReqError::invalid_request());
    }
    // Response code at offset 6..10 (big-endian).
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    // TPM_RC_SUCCESS (0) or TPM_RC_INITIALIZE (0x100) when already started.
    if rc != 0 && rc != 0x100 {
        log::error!("VTPM: early TPM2_Startup rc=0x{rc:x}");
        return Err(SvsmReqError::invalid_request());
    }
    log::info!("VTPM: early TPM2_Startup ok (rc=0x{rc:x})");
    Ok(())
}

/// Generate an AES-256 key and a GCM nonce from the platform entropy source
/// (RDSEED). Out-param form: avoids 49-byte aggregate return that forces sret
/// and was implicated in a release-mode `%rbx` corruption on caller side.
pub(crate) fn platform_entropy(
    key: &mut [u8; 32],
    nonce: &mut [u8; 12],
) -> Result<(), SvsmReqError> {
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

    Ok(())
}

/// Zeroize key material in-place using volatile writes.
pub(crate) fn zeroize_key_material(aes_key: &[u8; 32], nonce: &[u8; 12]) {
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
#[inline] // R1: avoid sret aggregate-return on Vec<u8>
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
