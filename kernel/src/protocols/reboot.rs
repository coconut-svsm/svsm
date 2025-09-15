// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 AMD, Inc.
//
// Author: Richard Relph <richard.relph@amd.com

/// Reboot protocol commands (SVSM spec, Chapter 11)
extern crate alloc;

use alloc::vec::Vec;

use crate::protocols::core::invalidate_guest_pages;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::msr_protocol::request_termination_msr;

// Reboot protocol services (SVSM spec, Chapter 11)
const SVSM_REBOOT_EXECUTE: u32 = 0;

pub const REBOOT_PROTOCOL_VERSION_MIN: u32 = 1;
pub const REBOOT_PROTOCOL_VERSION_MAX: u32 = 1;

pub fn reboot_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_REBOOT_EXECUTE => reboot_execute_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}

// SVSM_REBOOT_EXECUTE as defined in SVSM Spec, Section 11.1
fn reboot_execute_request(params: &RequestParams) -> Result<(), SvsmReqError> {
    if params.rcx != 0 {
        request_termination_msr();
    }
    invalidate_guest_pages();
    match crate::platform::SVSM_PLATFORM.relaunch_fw() {
        Ok(()) => Ok(()),
        Err(_) => request_termination_msr(),
    }
}

/// Get the Reboot manifest. Used by the SVSM Attestation protocol (SVSM Spec Chapter 7)
pub fn reboot_get_manifest() -> Result<Vec<u8>, SvsmReqError> {
    let manifest = RebootManifest {
        version: 0,
        flags: 0,
    };
    Ok(manifest.to_vec())
}

// Reboot Manifest Data Structure as defined in the SVSM Spec, Section 11.2
struct RebootManifest {
    version: u32,
    flags: u32,
}

impl RebootManifest {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.version.to_le_bytes());
        vec.extend_from_slice(&self.flags.to_le_bytes());
        vec
    }
}
