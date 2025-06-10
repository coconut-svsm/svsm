// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM Corp
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! vTPM protocol implementation (SVSM spec, chapter 8).

extern crate alloc;

use alloc::vec::Vec;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    address::{Address, PhysAddr},
    mm::guestmem::{copy_slice_to_guest, read_bytes_from_guest, read_from_guest},
    protocols::{errors::SvsmReqError, RequestParams},
    types::PAGE_SIZE,
    vtpm::{vtpm_get_locked, TcgTpmSimulatorInterface, VtpmProtocolInterface},
};

/// vTPM platform commands (SVSM spec, section 8.1 - SVSM_VTPM_QUERY)
///
/// The platform commmand values follow the values used by the
/// Official TPM 2.0 Reference Implementation by Microsoft.
///
/// `tpm-20-ref/TPMCmd/Simulator/include/TpmTcpProtocol.h`
#[repr(u32)]
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum TpmPlatformCommand {
    SendCommand = 8,
}

impl TryFrom<u32> for TpmPlatformCommand {
    type Error = SvsmReqError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let cmd = match value {
            x if x == TpmPlatformCommand::SendCommand as u32 => TpmPlatformCommand::SendCommand,
            other => {
                log::warn!("Failed to convert {} to a TPM platform command", other);
                return Err(SvsmReqError::invalid_parameter());
            }
        };

        Ok(cmd)
    }
}

fn vtpm_platform_commands_supported_bitmap() -> u64 {
    let mut bitmap: u64 = 0;
    let vtpm = vtpm_get_locked();

    for cmd in vtpm.get_supported_commands() {
        bitmap |= 1u64 << *cmd as u32;
    }

    bitmap
}

fn is_vtpm_platform_command_supported(cmd: TpmPlatformCommand) -> bool {
    let vtpm = vtpm_get_locked();
    vtpm.get_supported_commands().iter().any(|x| *x == cmd)
}

const SEND_COMMAND_REQ_INBUF_SIZE: usize = PAGE_SIZE - 9;

// vTPM protocol services (SVSM spec, table 14)
const SVSM_VTPM_QUERY: u32 = 0;
const SVSM_VTPM_COMMAND: u32 = 1;

/// TPM_SEND_COMMAND request structure (SVSM spec, table 16)
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
struct TpmSendCommandRequest {
    /// MSSIM platform command ID
    command: u32,
    /// Locality usage for the vTPM is not defined yet (must be zero)
    locality: u8,
    /// Size of the input buffer
    inbuf_size: u32,
    /// Input buffer that contains the TPM command
    inbuf: [u8; SEND_COMMAND_REQ_INBUF_SIZE],
}

impl TpmSendCommandRequest {
    // Take as slice and return a reference for Self
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let request =
            Self::ref_from_bytes(buffer).map_err(|_| SvsmReqError::invalid_parameter())?;

        if !request.validate() {
            return Err(SvsmReqError::invalid_parameter());
        }

        Ok(request)
    }

    fn validate(&self) -> bool {
        // TODO: Before implementing locality, we need to agree what it means
        // to the platform
        self.locality == 0
            && self.command == TpmPlatformCommand::SendCommand as u32
            && self.inbuf_size as usize <= SEND_COMMAND_REQ_INBUF_SIZE
    }

    pub fn send(&self) -> Result<Vec<u8>, SvsmReqError> {
        let length = self.inbuf_size as usize;

        let tpm_cmd = self
            .inbuf
            .get(..length)
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        let vtpm = vtpm_get_locked();
        let response = vtpm.send_tpm_command(tpm_cmd, self.locality)?;

        Ok(response)
    }
}

const SEND_COMMAND_RESP_OUTBUF_SIZE: usize = PAGE_SIZE - 4;

/// TPM_SEND_COMMAND response structure (SVSM spec, table 17)
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
struct TpmSendCommandResponse {
    /// Size of the output buffer
    outbuf_size: u32,
    /// Output buffer that will hold the command response
    outbuf: [u8; SEND_COMMAND_RESP_OUTBUF_SIZE],
}

impl TpmSendCommandResponse {
    // Take as slice and return a &mut Self
    pub fn try_from_as_mut_ref(buffer: &mut [u8]) -> Result<&mut Self, SvsmReqError> {
        Self::mut_from_bytes(buffer).map_err(|_| SvsmReqError::invalid_parameter())
    }

    /// Write the response to the outbuf
    ///
    /// # Arguments
    ///
    /// * `response`: TPM_SEND_COMMAND response slice
    pub fn set_outbuf(&mut self, response: &[u8]) -> Result<(), SvsmReqError> {
        self.outbuf
            .get_mut(..response.len())
            .ok_or_else(SvsmReqError::invalid_request)?
            .copy_from_slice(response);
        self.outbuf_size = response.len() as u32;

        Ok(())
    }
}

fn vtpm_query_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // Bitmap of the supported vTPM commands
    params.rcx = vtpm_platform_commands_supported_bitmap();
    // Supported vTPM features. Must-be-zero
    params.rdx = 0;

    Ok(())
}

/// Send a TpmSendCommandRequest to the vTPM
///
/// # Arguments
///
/// * `buffer`: Contains the TpmSendCommandRequest. It will also be
///   used to store the TpmSendCommandResponse as a byte slice
fn tpm_send_command_request(buffer: &mut [u8]) -> Result<(), SvsmReqError> {
    let outbuf: Vec<u8> = {
        let request = TpmSendCommandRequest::try_from_as_ref(buffer)?;
        request.send()?
    };
    let response = TpmSendCommandResponse::try_from_as_mut_ref(buffer)?;
    let _ = response.set_outbuf(outbuf.as_slice());

    Ok(())
}

fn vtpm_command_request(params: &RequestParams) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(params.rcx);

    if paddr.is_null() {
        return Err(SvsmReqError::invalid_parameter());
    }

    // vTPM common request/response structure (SVSM spec, table 15)
    //
    // First 4 bytes are used as input and output.
    //     IN: platform command
    //    OUT: platform command response size

    let command = read_from_guest::<u32>(paddr).map_err(|_| SvsmReqError::invalid_parameter())?;

    let cmd = TpmPlatformCommand::try_from(command)?;

    if !is_vtpm_platform_command_supported(cmd) {
        return Err(SvsmReqError::unsupported_call());
    }

    match cmd {
        TpmPlatformCommand::SendCommand => {
            // The vTPM buffer size is one page, but it not required to be page aligned.
            let mut buffer = read_bytes_from_guest(paddr, PAGE_SIZE)?;
            tpm_send_command_request(&mut buffer[..])?;
            copy_slice_to_guest(&buffer[..], paddr)?;
        }
    };

    Ok(())
}

pub fn vtpm_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_VTPM_QUERY => vtpm_query_request(params),
        SVSM_VTPM_COMMAND => vtpm_command_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
