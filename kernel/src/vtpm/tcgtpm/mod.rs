// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate implements the virtual TPM interfaces for the TPM 2.0
//! Reference Implementation (by Microsoft)

/// Functions required to build the TPM 2.0 Reference Implementation libraries
#[cfg(target_os = "none")]
mod wrapper;

pub mod ek_templates;
mod tss;

extern crate alloc;

use alloc::vec::Vec;

use core::ffi::c_void;
use libtcgtpm::bindings::{
    _plat__LocalitySet, _plat__NVDisable, _plat__NVEnable, _plat__RunCommand, _plat__SetNvAvail,
    _plat__Signal_PowerOn, _plat__Signal_Reset, TPM_Manufacture, TPM_TearDown,
};

use crate::{
    address::VirtAddr,
    protocols::{errors::SvsmReqError, vtpm::TpmPlatformCommand},
    types::PAGE_SIZE,
    vtpm::{
        TcgTpmSimulatorInterface, VtpmInterface, VtpmProtocolInterface,
        tcgtpm::ek_templates::DEFAULT_PUBLIC_AREA,
    },
};

#[derive(Debug, Clone, Default)]
pub struct TcgTpm {
    is_powered_on: bool,
    ekpub: Option<Vec<u8>>,
}

impl TcgTpm {
    pub const fn new() -> TcgTpm {
        TcgTpm {
            is_powered_on: false,
            ekpub: None,
        }
    }

    fn teardown(&self) -> Result<(), SvsmReqError> {
        // SAFETY: FFI call. Return value is checked.
        let result = unsafe { TPM_TearDown() };
        match result {
            0 => Ok(()),
            rc => {
                log::error!("TPM_Teardown failed rc={rc}");
                Err(SvsmReqError::incomplete())
            }
        }
    }

    fn manufacture(&self, first_time: i32) -> Result<i32, SvsmReqError> {
        // SAFETY: FFI call. Parameter and return values are checked.
        let result = unsafe { TPM_Manufacture(first_time) };
        match result {
            // TPM manufactured successfully
            0 => Ok(0),
            // TPM already manufactured
            1 => Ok(1),
            // TPM failed to manufacture
            rc => {
                log::error!("TPM_Manufacture failed rc={rc}");
                Err(SvsmReqError::incomplete())
            }
        }
    }
}

const TPM_CMDS_SUPPORTED: &[TpmPlatformCommand] = &[TpmPlatformCommand::SendCommand];

impl VtpmProtocolInterface for TcgTpm {
    fn get_supported_commands(&self) -> &[TpmPlatformCommand] {
        TPM_CMDS_SUPPORTED
    }
}

pub const TPM_BUFFER_MAX_SIZE: usize = PAGE_SIZE;

impl TcgTpmSimulatorInterface for TcgTpm {
    #[inline] // R1: avoid sret aggregate-return on Vec<u8>
    fn send_tpm_command(&self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        if command.len() > TPM_BUFFER_MAX_SIZE {
            return Err(SvsmReqError::invalid_parameter());
        }

        // _plat__RunCommand() should define it `const` because it only uses
        // it as input, but unfortunately it doesn't. Anyway, this buffer
        // is only read during the FFI call.
        let request_ffi_p = command.as_ptr() as *mut u8;
        let request_ffi_size = command.len() as u32;

        let mut response_ffi = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
        let mut response_ffi_p = response_ffi.as_mut_ptr();
        let mut response_ffi_size = TPM_BUFFER_MAX_SIZE as u32;

        // SAFETY: FFI calls. Parameters are checked. Both calls are void,
        // _plat__RunCommand() returns `response_ffi_size` value by reference
        // and it is validated.
        unsafe {
            _plat__LocalitySet(locality);
            _plat__RunCommand(
                request_ffi_size,
                request_ffi_p,
                &raw mut response_ffi_size,
                &raw mut response_ffi_p,
            );
            if response_ffi_size == 0 || response_ffi_size as usize > response_ffi.capacity() {
                return Err(SvsmReqError::invalid_request());
            }
            // In TPM failure mode, _plat__RunCommand() redirects the response
            // pointer to an internal static buffer instead of writing into the
            // provided one.
            if response_ffi_p != response_ffi.as_mut_ptr() {
                core::ptr::copy(
                    response_ffi_p,
                    response_ffi.as_mut_ptr(),
                    response_ffi_size as usize,
                );
            }
            response_ffi.set_len(response_ffi_size as usize);
        }

        // A3 — runtime re-seal hook.
        //
        // The vTPM persistence cycle seals at Provision/Recover time but never
        // commits guest-runtime NV writes (e.g. `tpm2_nvwrite` between boots).
        // Sniff TPM2_Shutdown(SU_STATE) as a natural re-seal trigger: TCG
        // semantics say the OS is about to lose volatile state, which is exactly
        // the moment we need to persist g* + s_NV into a fresh SealedBlob.
        //
        // The hook is a no-op when:
        //   - the command is not TPM2_Shutdown (cmdCode != 0x00000145), or
        //   - Shutdown itself returned non-success (avoid re-sealing inconsistent state).
        //
        // The hook never propagates failure — re-seal errors are logged; the
        // guest still sees its real Shutdown rc. fail-closed is enforced on the
        // next cold boot's unseal path (NV-counter check + AES-GCM tag verify).
        #[cfg(feature = "vtpm-persist")]
        crate::vtpm::reseal::trigger_if_shutdown(command, &response_ffi);

        Ok(response_ffi)
    }

    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError> {
        if self.is_powered_on && !only_reset {
            return Ok(());
        }
        if only_reset && !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        if !only_reset {
            // SAFETY: FFI call. No parameter, return value is checked.
            let result = unsafe { _plat__Signal_PowerOn() };
            if result != 0 {
                log::error!("_plat__Signal_PowerOn failed rc={result}");
                return Err(SvsmReqError::incomplete());
            }
        }
        // It calls TPM_init() within to indicate that a TPM2_Startup is required.
        // SAFETY: FFI call. No parameter, return value is checked.
        let result = unsafe { _plat__Signal_Reset() };
        if result != 0 {
            log::error!("_plat__Signal_Reset failed rc={result}");
            return Err(SvsmReqError::incomplete());
        }
        self.is_powered_on = true;

        Ok(())
    }

    fn signal_nvon(&self) -> Result<(), SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        // SAFETY: FFI call. No Parameters or return values.
        unsafe { _plat__SetNvAvail() };

        Ok(())
    }
}

impl VtpmInterface for TcgTpm {
    #[inline] // R1: avoid sret aggregate-return on Vec<u8>
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError> {
        if self.ekpub.is_none() {
            self.ekpub = Some(tss::create_ek(self, &DEFAULT_PUBLIC_AREA[..])?);
        }
        self.ekpub.clone().ok_or_else(SvsmReqError::invalid_request)
    }

    fn is_powered_on(&self) -> bool {
        self.is_powered_on
    }

    fn init(&mut self) -> Result<(), SvsmReqError> {
        // Initialize the TPM TCG following the same steps done in the Simulator:
        //
        // 1. Manufacture it for the first time
        // 2. Make sure it does not fail if it is re-manufactured
        // 3. Teardown to indicate it needs to be manufactured
        // 4. Manufacture it for the first time
        // 5. Power it on indicating it requires startup. By default, OVMF will start
        //    and selftest it.

        // SAFETY: FFI call. Parameters and return values are checked.
        let mut rc = unsafe { _plat__NVEnable(VirtAddr::null().as_mut_ptr::<c_void>(), 0) };
        if rc != 0 {
            log::error!("_plat__NVEnable failed rc={rc}");
            return Err(SvsmReqError::incomplete());
        }

        rc = self.manufacture(1)?;
        if rc != 0 {
            // SAFETY: FFI call. Parameter checked, no return value.
            unsafe { _plat__NVDisable(core::ptr::without_provenance_mut::<c_void>(1), 0) };
            return Err(SvsmReqError::incomplete());
        }

        rc = self.manufacture(0)?;
        if rc != 1 {
            return Err(SvsmReqError::incomplete());
        }

        self.teardown()?;
        rc = self.manufacture(1)?;
        if rc != 0 {
            return Err(SvsmReqError::incomplete());
        }

        self.signal_poweron(false)?;
        self.signal_nvon()?;

        log::info!("VTPM: TPM 2.0 Reference Implementation initialized");

        Ok(())
    }

    fn recover_init(&mut self) -> Result<(), SvsmReqError> {
        // Recover path: bring the platform layer up but DO NOT manufacture.
        // Manufacturing would re-seed EPS/SPS/PPS, destroying the
        // correspondence between the in-memory hierarchies and the keys
        // sealed in the SealedBlob. We need NVEnable so the simulator's
        // NV region is mapped, signal_poweron(false) so PowerOn+Reset
        // bring the globals up into a "needs TPM2_Startup" state, and
        // signal_nvon so NV-backed operations work.

        // SAFETY: FFI call. Parameters and return values are checked.
        let rc = unsafe { _plat__NVEnable(VirtAddr::null().as_mut_ptr::<c_void>(), 0) };
        if rc != 0 {
            log::error!("_plat__NVEnable (recover) failed rc={rc}");
            return Err(SvsmReqError::incomplete());
        }

        self.signal_poweron(false)?;
        self.signal_nvon()?;

        log::info!("VTPM: TPM 2.0 Reference Implementation initialized (Recover)");

        Ok(())
    }
}
