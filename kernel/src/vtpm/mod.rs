// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate defines the Virtual TPM interfaces and shows what
//! TPM backends are supported

/// TPM 2.0 Reference Implementation by Microsoft
pub mod mstpm;

use crate::protocols::vtpm::TpmPlatformCommand;
use crate::vtpm::mstpm::MsTpm as Vtpm;
use crate::{locking::SpinLock, protocols::errors::SvsmReqError};

/// Basic services required to perform the VTPM Protocol
pub trait VtpmProtocolInterface {
    /// Get the list of Platform Commands supported by the TPM implementation.
    fn get_supported_commands(&self) -> &[TpmPlatformCommand];
}

/// This implements one handler for each [`TpmPlatformCommand`] supported by the
/// VTPM Protocol. These handlers are based on the TPM Simulator
/// interface (by Microsoft), but with a few changes to make it more Rust
/// idiomatic.
///
/// `ms-tpm-20-ref/TPMCmd/Simulator/include/prototypes/Simulator_fp.h`
pub trait MsTpmSimulatorInterface: VtpmProtocolInterface {
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
pub trait VtpmInterface: MsTpmSimulatorInterface {
    /// Check if the TPM is powered on.
    fn is_powered_on(&self) -> bool;

    /// Prepare the TPM to be used for the first time. At this stage,
    /// the TPM is manufactured.
    fn init(&mut self) -> Result<(), SvsmReqError>;
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
