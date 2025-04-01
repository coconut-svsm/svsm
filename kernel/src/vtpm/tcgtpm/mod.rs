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
        tcgtpm::ek_templates::DEFAULT_PUBLIC_AREA, SvsmVTpmError, TcgTpmSimulatorInterface,
        VtpmInterface, VtpmProtocolInterface,
    },
};

// Definitions from "Trusted Platform Module Library Part 4: Supporting Routines – Code,
// Family “2.0”, Level 00, Revision 01.38"

const TPM_RC_SUCCESS: u32 = 0;

// This selector is similar to the template selector, except the whole public key template
// is part of the selector. There is no support for PCR selection or inSensitive or outsideInfo.
const VTPM_SELECT_MTAUTH_EK: u64 = 0x0000_0000_0000_0001;

#[derive(Debug, Clone, Default)]
pub struct TcgTpm {
    is_powered_on: bool,
    ekpub: Option<Vec<u8>>,
}

// PREREQUISITE: CMD must be at least 10 bytes long.
// A TPM command result contains
//
// Byte offset | Size | Description
// ---
// 0x00        | 2    | u16 ST tag
// 0x02        | 4    | u32 response size
// 0x06        | 4    | u32 response code
fn tpm_cmd_rc(cmd: &[u8]) -> u32 {
    u32::from_be_bytes(cmd[6..10].try_into().unwrap())
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

    fn select_primary_key_manifest(&self, selector: &[u8]) -> Result<Vec<u8>, SvsmVTpmError> {
        let (mut cmd, mut command_size) = create_mtauth_ek_cmd(selector);

        self.send_tpm_command(&mut cmd[..], &mut command_size, 0)
            .map_err(SvsmVTpmError::ReqError)?;

        let rc = tpm_cmd_rc(&cmd);
        // Check that TPM_RC(UINT32) at byte offset 6 is 0x00000000 (TPM_RC_SUCCESS)
        if rc != TPM_RC_SUCCESS {
            return Err(SvsmVTpmError::CommandError(rc));
        }

        // Get size (UINT16) of TPMT_PUBLIC at offset 18.
        // Note this is output from the TPM, so its value is trusted.
        let size_of_tpmt_public = u16::from_be_bytes([cmd[18], cmd[19]]);
        Ok(cmd[20..(20 + size_of_tpmt_public) as usize].to_vec())
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

fn extend_empty_auth(buf: &mut Vec<u8>) {
    // TPM_RS_PW(4) + nonce(2) + attributes(1) + pw(2)
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x09, // Size
        // TPM_RS_PW
        0x40, 0x00, 0x00, 0x09, // nonce == empty buffer
        0x00, 0x00, // session attributes = continueSession = 0x01
        0x01, // password = empty buffer
        0x00, 0x00,
    ]);
}

fn create_mtauth_ek_cmd(public_area: &[u8]) -> (Vec<u8>, usize) {
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

    // TPM Command header
    cmd.extend_from_slice(&[
        0x80, 0x02, // TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x00, // Placeholder for command size
        0x00, 0x00, 0x01, 0x31, // TPM_CC_CREATEPRIMARY
        0x40, 0x00, 0x00, 0x0B, // TPM_RH_ENDORSEMENT
    ]);

    // Authorization block
    extend_empty_auth(&mut cmd);

    // inSensitive parameter
    //
    // TPM2B_SENSITIVE_CREATE structure is defined in
    // Table 132 — Definition of TPM2B_SENSITIVE_CREATE Structure,
    // Trusted Platform Module Library Part 2: Structures
    cmd.extend_from_slice(&[
        0x00, 0x04, // sensitive data size
        0x00, 0x00, 0x00, 0x00, // user auth
    ]);

    // inPublic parameter
    // parameters size
    cmd.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
    // parameters
    cmd.extend_from_slice(public_area);

    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // outsideInfo parameter
        0x00, 0x00, // pcr selection
    ]);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    (cmd, command_size)
}

fn split_selector(selector: &[u8]) -> Result<(u64, &[u8]), SvsmReqError> {
    if selector.len() < 8 {
        log::error!("unexpected manifest selector length {}", selector.len());
        return Err(SvsmReqError::invalid_parameter());
    }
    let tag = u64::from_le_bytes(selector[..8].try_into().unwrap());
    Ok((tag, &selector[8..]))
}

impl VtpmInterface for TcgTpm {
    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError> {
        if self.ekpub.is_none() {
            let (mut cmd, mut cmd_size) = create_mtauth_ek_cmd(&DEFAULT_PUBLIC_AREA[..]);
            self.send_tpm_command(&mut cmd, &mut cmd_size, 0)?;
            if tpm_cmd_rc(cmd.as_slice()) != TPM_RC_SUCCESS {
                return Err(SvsmReqError::incomplete());
            }
            let size_of_tpmt_public = u16::from_be_bytes([cmd[18], cmd[19]]);
            self.ekpub = Some(cmd[20..(20 + size_of_tpmt_public) as usize].to_vec());
        }
        self.ekpub.clone().ok_or_else(SvsmReqError::invalid_request)
    }

    fn select_manifest(&mut self, version: u32, selector: &[u8]) -> Result<Vec<u8>, SvsmVTpmError> {
        // The only supported selector version is 0.
        if version > 0 {
            log::error!("unexpected manifest version number {}", version);
            return Err(SvsmVTpmError::ReqError(SvsmReqError::invalid_parameter()));
        }

        let (tag, data) = split_selector(selector)?;
        // The only supported selection kind is an endorsement hierarchy primary key.
        match tag {
            VTPM_SELECT_MTAUTH_EK => self.select_primary_key_manifest(data),
            _ => {
                log::error!("unknown selector tag {}", tag);
                Err(SvsmVTpmError::ReqError(SvsmReqError::invalid_parameter()))
            }
        }
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
