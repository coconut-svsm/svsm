// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM Corp
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! vTPM protocol implementation (SVSM spec, chapter 8).

extern crate alloc;

use core::{mem::size_of, slice::from_raw_parts_mut};

use alloc::vec::Vec;

use crate::{
    address::{Address, PhysAddr},
    mm::{valid_phys_address, GuestPtr, PerCPUPageMappingGuard},
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
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
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
        let buffer = buffer
            .get(..size_of::<Self>())
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // SAFETY: TpmSendCommandRequest has no invalid representations, as it
        // is comprised entirely of integer types. It is repr(packed), so its
        // required alignment is simply 1. We have checked the size, so this
        // is entirely safe.
        let request = unsafe { &*buffer.as_ptr().cast::<Self>() };

        Ok(request)
    }

    pub fn send(&self) -> Result<Vec<u8>, SvsmReqError> {
        // TODO: Before implementing locality, we need to agree what it means
        // to the platform
        if self.locality != 0 {
            return Err(SvsmReqError::invalid_parameter());
        }

        let mut length = self.inbuf_size as usize;

        let tpm_cmd = self
            .inbuf
            .get(..length)
            .ok_or_else(SvsmReqError::invalid_parameter)?;
        let mut buffer: Vec<u8> = Vec::with_capacity(SEND_COMMAND_RESP_OUTBUF_SIZE);
        buffer.extend_from_slice(tpm_cmd);

        // The buffer slice must be large enough to hold the TPM command response
        buffer.resize(SEND_COMMAND_RESP_OUTBUF_SIZE, 0);

        let vtpm = vtpm_get_locked();
        vtpm.send_tpm_command(buffer.as_mut_slice(), &mut length, self.locality)?;

        if length > buffer.len() {
            return Err(SvsmReqError::invalid_request());
        }
        buffer.truncate(length);

        Ok(buffer)
    }
}

const SEND_COMMAND_RESP_OUTBUF_SIZE: usize = PAGE_SIZE - 4;

/// TPM_SEND_COMMAND response structure (SVSM spec, table 17)
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct TpmSendCommandResponse {
    /// Size of the output buffer
    outbuf_size: u32,
    /// Output buffer that will hold the command response
    outbuf: [u8; SEND_COMMAND_RESP_OUTBUF_SIZE],
}

impl TpmSendCommandResponse {
    // Take as slice and return a &mut Self
    pub fn try_from_as_mut_ref(buffer: &mut [u8]) -> Result<&mut Self, SvsmReqError> {
        let buffer = buffer
            .get_mut(..size_of::<Self>())
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // SAFETY: TpmSendCommandResponse has no invalid representations, as it
        // is comprised entirely of integer types. It is repr(packed), so its
        // required alignment is simply 1. We have checked the size, so this
        // is entirely safe.
        let response = unsafe { &mut *buffer.as_mut_ptr().cast::<Self>() };

        Ok(response)
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
///
/// # Returns
///
/// * `u32`: Number of bytes written back to `buffer` as part of
///   the TpmSendCommandResponse
fn tpm_send_command_request(buffer: &mut [u8]) -> Result<u32, SvsmReqError> {
    let outbuf: Vec<u8> = {
        let request = TpmSendCommandRequest::try_from_as_ref(buffer)?;
        request.send()?
    };
    let response = TpmSendCommandResponse::try_from_as_mut_ref(buffer)?;
    let _ = response.set_outbuf(outbuf.as_slice());

    Ok(outbuf.len() as u32)
}

fn vtpm_command_request(params: &RequestParams) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(params.rcx);

    if paddr.is_null() {
        return Err(SvsmReqError::invalid_parameter());
    }
    if !valid_phys_address(paddr) {
        return Err(SvsmReqError::invalid_address());
    }

    // The vTPM buffer size is one page, but it not required to be page aligned.
    let start = paddr.page_align();
    let offset = paddr.page_offset();
    let end = (paddr + PAGE_SIZE).page_align_up();

    let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
    let vaddr = guard.virt_addr() + offset;

    // vTPM common request/response structure (SVSM spec, table 15)
    //
    // First 4 bytes are used as input and output.
    //     IN: platform command
    //    OUT: platform command response size

    // SAFETY: vaddr comes from a new mapped region.
    let command = unsafe { GuestPtr::<u32>::new(vaddr).read()? };

    let cmd = TpmPlatformCommand::try_from(command)?;

    if !is_vtpm_platform_command_supported(cmd) {
        return Err(SvsmReqError::unsupported_call());
    }

    let buffer = unsafe { from_raw_parts_mut(vaddr.as_mut_ptr::<u8>(), PAGE_SIZE) };

    let response_size = match cmd {
        TpmPlatformCommand::SendCommand => tpm_send_command_request(buffer)?,
    };

    // SAFETY: vaddr points to a new mapped region.
    // if paddr + sizeof::<u32>() goes to the folowing page, it should
    // not be a problem since the end of the requested region is
    // (paddr + PAGE_SIZE), which requests another page. So
    // write(response_size) can only happen on valid memory, mapped
    // by PerCPUPageMappingGuard::create().
    unsafe {
        GuestPtr::<u32>::new(vaddr).write(response_size)?;
    }

    Ok(())
}

pub fn vtpm_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_VTPM_QUERY => vtpm_query_request(params),
        SVSM_VTPM_COMMAND => vtpm_command_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
