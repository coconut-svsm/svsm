// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025  Hewlett Packard Enterprise Development LP
// Copyright (c) Coconut-SVSM authors
//

// This module is an incomplete software stack for constructing commands to send to the TPM.
// It is not fully general for expressing all inputs to a command.

extern crate alloc;

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::{
    tcgtpm::{TcgTpmSimulatorInterface, TPM_BUFFER_MAX_SIZE},
    SvsmVTpmError,
};
use alloc::vec::Vec;

pub const TPM_RC_SUCCESS: u32 = 0;

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

fn create_mtauth_ek_cmd(tpmt_public: &[u8]) -> Vec<u8> {
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
    cmd.extend_from_slice(&(tpmt_public.len() as u16).to_be_bytes());
    // parameters
    cmd.extend_from_slice(tpmt_public);

    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // outsideInfo parameter
        0x00, 0x00, // pcr selection
    ]);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    cmd
}

/// Sends `cmd` to `vtpm` and returns the interpretation of its error mode.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `cmd`: A command buffer large enough to receive the command response.
/// * `set_len`: If true, sets the command length in the command header to `cmd.len()` before
///   sending the command.
pub fn checked_send<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    cmd: &mut [u8],
    set_len: bool,
) -> Result<(), SvsmVTpmError> {
    let mut command_size;
    if set_len {
        command_size = cmd.len();
        cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());
    } else {
        command_size = u32::from_be_bytes(cmd[2..6].try_into().unwrap()) as usize;
    }
    vtpm.send_tpm_command(cmd, &mut command_size, 0)
        .map_err(|_| SvsmVTpmError::ReqError(SvsmReqError::invalid_request()))?;
    let rc = tpm_cmd_rc(cmd);
    if rc != TPM_RC_SUCCESS {
        return Err(SvsmVTpmError::CommandError(rc));
    }
    Ok(())
}

/// Uses `vtpm` to create an a primary key on the endorsement hierarchy.
///
/// The key has no authorization policy.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `tpmt_public`: A marshaled TPMT_PUBLIC to use as the key creation template.
///
/// Returns:
///
/// A TPMT_PUBLIC of the key created from the template.
pub fn create_ek<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    tpmt_public: &[u8],
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = create_mtauth_ek_cmd(tpmt_public);

    checked_send(vtpm, &mut cmd, /*set_len=*/ false)?;

    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    let size_of_tpmt_public = u16::from_be_bytes([cmd[18], cmd[19]]);
    Ok(cmd[20..(20 + size_of_tpmt_public) as usize].to_vec())
}
