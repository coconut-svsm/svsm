// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate defines the Virtual TPM interfaces and shows what
//! TPM backends are supported

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
    /// * `buffer`: Buffer with the command to be sent to the TPM. It has to be large enough
    ///             to hold the response received from the TPM.
    /// * `length`: The length of the command stored in `buffer`. It will be updated with the
    ///             size of the TPM response received from the TPM.
    /// * `locality`: TPM locality the TPM command will be executed
    fn send_tpm_command(
        &self,
        buffer: &mut [u8],
        length: &mut usize,
        locality: u8,
    ) -> Result<(), SvsmReqError>;

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

/// Basic TPM driver services
pub trait VtpmInterface: TcgTpmSimulatorInterface {
    /// Check if the TPM is powered on.
    fn is_powered_on(&self) -> bool;

    /// Prepare the TPM to be used for the first time. At this stage,
    /// the TPM is manufactured.
    fn init(&mut self) -> Result<(), SvsmReqError>;

    /// Create RSA 2048 Endorsement Key (EK) and cache the public key
    ///
    /// This function creates an RSA 2048-bit Endorsement Key (EK) from the TPM's Endorsement
    /// Primary Seed (EPS) and caches the public key as TMPT_PUBLIC structure. The cached EK
    /// public key can be retrieved later and used to  provide  vTPM service attestation. The
    /// EK is created with the TCG default EK template as shown in Table 4 of the "TCG EK
    /// Credential Profile For TPM Family 2.0; Level 0 Version 2.5 Revision 2.0".
    ///
    /// Since the EK is created from the EPS, following the TCG EK Credential Profile, the EK can
    /// be recreated at any time. For example, one can recreate the same EK in an OS using TSS2
    /// "tpm2_createek -c ek.ctx -G rsa -u ek.pub command".
    ///
    /// Retrieve the EK public key with get_ekpub() function.
    fn create_ek_rsa2048(&mut self) -> Result<(), SvsmReqError>;

    /// Returns the cached EK public key if it exists, otherwise it returns an error indicating
    /// that the EK public key does not exist.
    fn get_ekpub(&self) -> Result<Vec<u8>, SvsmReqError>;

    /// Run the TPM self-test command
    fn run_selftest_cmd(&self) -> Result<(), SvsmReqError>;

    // Run the TPM startup command
    fn run_startup_cmd(&self) -> Result<(), SvsmReqError>;
}

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

pub fn vtpm_get_locked<'a>() -> LockGuard<'a, Vtpm> {
    VTPM.lock()
}

/// Get the TPM EK public key by calling the get_ekpub() implementation of the
/// [`VtpmInterface`]
pub fn vtpm_get_ekpub() -> Result<Vec<u8>, SvsmReqError> {
    let vtpm = VTPM.lock();
    vtpm.get_ekpub()
}
