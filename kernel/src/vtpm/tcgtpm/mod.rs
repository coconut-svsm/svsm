// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate implements the virtual TPM interfaces for the TPM 2.0
//! Reference Implementation (by Microsoft)

/// Functions required to build the TPM 2.0 Reference Implementation libraries
#[cfg(not(any(test, fuzzing)))]
mod wrapper;

pub mod ek_templates;
mod tss;

extern crate alloc;

use alloc::vec::Vec;

use core::ffi::c_void;
use libtcgtpm::bindings::{
    TPM_Manufacture, TPM_TearDown, _plat__LocalitySet, _plat__NVDisable, _plat__NVEnable,
    _plat__RunCommand, _plat__SetNvAvail, _plat__Signal_PowerOn, _plat__Signal_Reset,
};

use crate::{
    address::VirtAddr,
    protocols::{errors::SvsmReqError, vtpm::TpmPlatformCommand},
    types::PAGE_SIZE,
    vtpm::{
        tcgtpm::ek_templates::DEFAULT_PUBLIC_AREA, TcgTpmSimulatorInterface, VtpmInterface,
        VtpmProtocolInterface,
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
                log::error!("TPM_Teardown failed rc={}", rc);
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
                log::error!("TPM_Manufacture failed rc={}", rc);
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
    fn send_tpm_command(
        &self,
        buffer: &mut [u8],
        length: &mut usize,
        locality: u8,
    ) -> Result<(), SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        if *length > TPM_BUFFER_MAX_SIZE || *length > buffer.len() {
            return Err(SvsmReqError::invalid_parameter());
        }

        let mut request_ffi = buffer[..*length].to_vec();

        let mut response_ffi = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
        let mut response_ffi_p = response_ffi.as_mut_ptr();
        let mut response_ffi_size = TPM_BUFFER_MAX_SIZE as u32;

        // SAFETY: FFI calls. Parameters are checked. Both calls are void,
        // _plat__RunCommand() returns `response_ffi_size` value by reference
        // and it is validated.
        unsafe {
            _plat__LocalitySet(locality);
            _plat__RunCommand(
                request_ffi.len() as u32,
                request_ffi.as_mut_ptr().cast::<u8>(),
                &raw mut response_ffi_size,
                &raw mut response_ffi_p,
            );
            if response_ffi_size == 0 || response_ffi_size as usize > response_ffi.capacity() {
                return Err(SvsmReqError::invalid_request());
            }
            response_ffi.set_len(response_ffi_size as usize);
        }

        buffer.fill(0);
        buffer
            .get_mut(..response_ffi.len())
            .ok_or_else(SvsmReqError::invalid_request)?
            .copy_from_slice(response_ffi.as_slice());
        *length = response_ffi.len();

        Ok(())
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
                log::error!("_plat__Signal_PowerOn failed rc={}", result);
                return Err(SvsmReqError::incomplete());
            }
        }
        // It calls TPM_init() within to indicate that a TPM2_Startup is required.
        // SAFETY: FFI call. No parameter, return value is checked.
        let result = unsafe { _plat__Signal_Reset() };
        if result != 0 {
            log::error!("_plat__Signal_Reset failed rc={}", result);
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
            log::error!("_plat__NVEnable failed rc={}", rc);
            return Err(SvsmReqError::incomplete());
        }

        rc = self.manufacture(1)?;
        if rc != 0 {
            // SAFETY: FFI call. Parameter checked, no return value.
            unsafe { _plat__NVDisable(1 as *mut c_void, 0) };
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
}
