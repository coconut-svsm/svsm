// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate implements the virtual TPM interfaces for the TPM 2.0
//! Reference Implementation (by Microsoft)

/// Functions required to build the TPM 2.0 Reference Implementation libraries
#[cfg(not(any(test, fuzzing)))]
mod wrapper;

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
    vtpm::{TcgTpmSimulatorInterface, VtpmInterface, VtpmProtocolInterface},
};

// Definitions from "Trusted Platform Module Library Part 4: Supporting Routines – Code,
// Family “2.0”, Level 00, Revision 01.38"
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_CREATEPRIMARY: u32 = 0x00000131;
const TPM_RH_ENDORSEMENT: u32 = 0x4000000B;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_KEY_BITS_2048: u16 = 2048;
const TPM_RS_PW: u32 = 0x40000009;

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
            log::error!("TPM is not powered on");
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

impl VtpmInterface for TcgTpm {
    fn run_selftest_cmd(&self) -> Result<(), SvsmReqError> {
        // TPM2_CC_SelfTest
        let selftest_cmd: &mut [u8] = &mut [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x00,
        ];
        self.send_tpm_command(selftest_cmd, &mut selftest_cmd.len(), 0)?;

        Ok(())
    }

    fn run_startup_cmd(&self) -> Result<(), SvsmReqError> {
        // TPM2_CC_Startup
        let startup_cmd: &mut [u8] = &mut [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        self.send_tpm_command(startup_cmd, &mut startup_cmd.len(), 0)?;

        Ok(())
    }

    fn get_ekpub(&self) -> Result<Vec<u8>, SvsmReqError> {
        self.ekpub.clone().ok_or_else(SvsmReqError::invalid_request)
    }

    fn create_ek_rsa2048(&mut self) -> Result<(), SvsmReqError> {
        // Creates RSA 2048-bit EK using TPM2_CreatePrimary command and TCG default EK template
        //
        // TPM2_CreatePrimary command is defined in Table 173 — TPM2_CreatePrimary Command, 365 of
        // "Trusted Platform Module Library Part 3: Commands-Codes, Family “2.0”, Level 00,
        // Revision 01.38".
        //
        // The TCG default EK template is defined in "Table 2: Default EK Template (TPMT_PUBLIC)
        // L-1: RSA 2048 (Storage)" of "TCG EK Credential Profile For TPM Family 2.0; Level 0
        // Version 2.5 Revision 2".
        //
        // See also "TCG TSS 2.0 Overview and Common Structures Specification, Version 1.0,
        // Level 2 Revision 10".
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }

        let authpolicy: [u8; 32] = [
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5,
            0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b,
            0x33, 0x14, 0x69, 0xaa,
        ];

        let object_attributes: u32 = 0x000300b2;

        // See Table 12 — Password Authorization Command of
        // Trusted Platform Module Library Part 1: Architecture,
        // Family “2.0”, Level 00, Revision 01.38
        let mut auth_block: Vec<u8> = Vec::new();
        auth_block.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        // nonce == empty buffer
        auth_block.extend_from_slice(&[0x00, 0x00]);
        // session attributes = continueSession = 0x01
        auth_block.extend_from_slice(&[0x01]);
        // password = empty buffer
        auth_block.extend_from_slice(&[0x00, 0x00]);

        // TPM2B_PUBLIC with TCG default EK template,
        // see Table 2: Default EK Template (TPMT_PUBLIC) L-1: RSA 2048 (Storage)
        // of TCG EK Credential Profile For TPM Family 2.0; Level 0 Version 2.5 Revision 2
        let mut public_area: Vec<u8> = Vec::new();
        // type
        public_area.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        // nameAlg
        public_area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        // objectAttributes
        public_area.extend_from_slice(&object_attributes.to_be_bytes());
        // authPolicy size
        public_area.extend_from_slice(&(authpolicy.len() as u16).to_be_bytes());
        // authPolicy
        public_area.extend_from_slice(authpolicy.as_slice());
        // parameters
        // symmetric algorithm
        public_area.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        // symmetric keyBits
        public_area.extend_from_slice(&128_u16.to_be_bytes());
        // symmetric mode
        public_area.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());

        // scheme
        public_area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        // keyBits
        public_area.extend_from_slice(&TPM_KEY_BITS_2048.to_be_bytes());
        // exponent
        public_area.extend_from_slice(&0_u32.to_be_bytes());

        // unique size
        public_area.extend_from_slice(&256_u16.to_be_bytes());
        // unique
        public_area.extend_from_slice(&[0x00; 256]);

        let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

        // TPM Command header
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        // Placeholder for command size
        cmd.extend_from_slice(&(0u32).to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_CREATEPRIMARY.to_be_bytes());
        cmd.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());

        // Authorization block
        cmd.extend_from_slice(&(auth_block.len() as u32).to_be_bytes());
        cmd.extend_from_slice(auth_block.as_slice());

        // inSensitive parameter
        //
        // TPM2B_SENSITIVE_CREATE structure is defined in
        // Table 132 — Definition of TPM2B_SENSITIVE_CREATE Structure,
        // Trusted Platform Module Library Part 2: Structures
        // sensitive data size
        cmd.extend_from_slice(&4_u16.to_be_bytes());
        // user auth
        cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // inPublic parameter
        // parameters size
        cmd.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        // parameters
        cmd.extend_from_slice(public_area.as_slice());

        // outsideInfo parameter
        cmd.extend_from_slice(&0_u32.to_be_bytes());
        cmd.extend_from_slice(&0_u16.to_be_bytes());

        // Update command size
        let mut command_size = cmd.len();
        cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

        cmd.resize(TPM_BUFFER_MAX_SIZE, 0);

        self.send_tpm_command(&mut cmd[..], &mut command_size, 0)?;

        // Check that TPM_RC(UINT32) at byte offset 6 is 0x00000000 (TPM_RC_SUCCESS)
        if cmd[6..10] != [0x00, 0x00, 0x00, 0x00] {
            return Err(SvsmReqError::incomplete());
        }

        // Get size (UINT16) of TPMT_PUBLIC at offset 18
        let size_of_tpmt_public = u16::from_be_bytes([cmd[18], cmd[19]]);
        self.ekpub = Some(cmd[20..(20 + size_of_tpmt_public) as usize].to_vec());

        Ok(())
    }

    fn is_powered_on(&self) -> bool {
        self.is_powered_on
    }

    fn init(&mut self) -> Result<(), SvsmReqError> {
        // Initialize the TPM TCG following the same steps done in the Simulator and generate EK:
        //
        // 1. Manufacture it for the first time
        // 2. Make sure it does not fail if it is re-manufactured
        // 3. Teardown to indicate it needs to be manufactured
        // 4. Manufacture it for the first time
        // 5. Power it on indicating it requires startup. By default, OVMF will start
        //    and selftest it.
        // 6. Selftest it
        // 7. Start it up  on for next step
        // 8. Create RSA2004 EK and cache EKpub for VTPM service attestation requests
        //
        // Since we have already run TPM2_Startup here, when OVMF runs TPM2_Startup, it will
        // get back TPM_RC_INITIALIZE indicating that TPM2_Startup is not required. See,
        // https://github.com/tianocore/edk2/blob/master/SecurityPkg/Library/Tpm2CommandLib/Tpm2Startup.c#L75

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

        self.run_selftest_cmd()?;
        self.run_startup_cmd()?;

        self.create_ek_rsa2048()?;

        log::info!("VTPM: TPM 2.0 Reference Implementation initialized");

        Ok(())
    }
}
