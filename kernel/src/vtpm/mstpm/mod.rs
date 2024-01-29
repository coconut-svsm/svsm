// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate implements the virtual TPM interfaces for the TPM 2.0
//! Reference Implementation (by Microsoft)

/// Functions required to build the Microsoft TPM libraries
mod wrapper;

extern crate alloc;

use alloc::vec::Vec;
use core::{ffi::c_void, ptr::addr_of_mut};
use libmstpm::bindings::{
    TPM_Manufacture, TPM_TearDown, _plat__LocalitySet, _plat__NVDisable, _plat__NVEnable,
    _plat__RunCommand, _plat__SetNvAvail, _plat__Signal_PowerOn, _plat__Signal_Reset,
};

use crate::{
    address::VirtAddr,
    protocols::{errors::SvsmReqError, vtpm::TpmPlatformCommand},
    types::PAGE_SIZE,
    vtpm::{MsTpmSimulatorInterface, VtpmInterface, VtpmProtocolInterface},
};

#[derive(Debug, Copy, Clone)]
pub struct MsTpm {
    is_powered_on: bool,
}

impl MsTpm {
    pub const fn new() -> MsTpm {
        MsTpm {
            is_powered_on: false,
        }
    }

    fn teardown(&self) -> Result<(), SvsmReqError> {
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

impl VtpmProtocolInterface for MsTpm {
    fn get_supported_commands(&self) -> &[TpmPlatformCommand] {
        TPM_CMDS_SUPPORTED
    }
}

pub const TPM_BUFFER_MAX_SIZE: usize = PAGE_SIZE;

impl MsTpmSimulatorInterface for MsTpm {
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

        unsafe {
            _plat__LocalitySet(locality);
            _plat__RunCommand(
                request_ffi.len() as u32,
                request_ffi.as_mut_ptr().cast::<u8>(),
                addr_of_mut!(response_ffi_size),
                addr_of_mut!(response_ffi_p),
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
            unsafe { _plat__Signal_PowerOn() };
        }
        // It calls TPM_init() within to indicate that a TPM2_Startup is required.
        unsafe { _plat__Signal_Reset() };
        self.is_powered_on = true;

        Ok(())
    }

    fn signal_nvon(&self) -> Result<(), SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        unsafe { _plat__SetNvAvail() };

        Ok(())
    }
}

impl VtpmInterface for MsTpm {
    fn is_powered_on(&self) -> bool {
        self.is_powered_on
    }

    fn init(&mut self) -> Result<(), SvsmReqError> {
        // Initialize the MS TPM following the same steps done in the Simulator:
        //
        // 1. Manufacture it for the first time
        // 2. Make sure it does not fail if it is re-manufactured
        // 3. Teardown to indicate it needs to be manufactured
        // 4. Manufacture it for the first time
        // 5. Power it on indicating it requires startup. By default, OVMF will start
        //    and selftest it.

        unsafe { _plat__NVEnable(VirtAddr::null().as_mut_ptr::<c_void>()) };

        let mut rc = self.manufacture(1)?;
        if rc != 0 {
            unsafe { _plat__NVDisable(1) };
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

        log::info!("VTPM: Microsoft TPM 2.0 initialized");

        Ok(())
    }
}
