// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) SUSE LLC
//
// Author: Vaishali Thakkar <vaishali.thakkar@suse.com>

//! `SNP_GUEST_REQUEST` command to request Secure TSC information.

use core::mem::{offset_of, size_of};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::error::SvsmError;

const TSC_INFO_REQ_SIZE: usize = 128;

/// MSG_TSC_INFO_REQ payload format.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct SnpTscInfoRequest {
    /// Reserved, must be zero.
    reserved: [u8; TSC_INFO_REQ_SIZE],
}

impl SnpTscInfoRequest {
    pub const fn new() -> Self {
        Self {
            reserved: [0; TSC_INFO_REQ_SIZE],
        }
    }
}

impl Default for SnpTscInfoRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// MSG_TSC_INFO_RSP payload format.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub struct SnpTscInfoResponse {
    status: u32,
    reserved_04: u32,
    tsc_scale: u64,
    tsc_offset: u64,
    tsc_factor: u32,
    reserved_1c: [u8; 100],
}

impl SnpTscInfoResponse {
    pub fn validate(&self) -> Result<(), SvsmError> {
        if self.status != 0 {
            return Err(SvsmError::SnpGuestRequest(self.status));
        }

        if self.reserved_04 != 0 || self.reserved_1c.iter().any(|&x| x != 0) {
            return Err(SvsmError::InvalidFormat);
        }

        Ok(())
    }

    pub fn tsc_scale(&self) -> u64 {
        self.tsc_scale
    }

    pub fn tsc_offset(&self) -> u64 {
        self.tsc_offset
    }

    pub fn tsc_factor(&self) -> u32 {
        self.tsc_factor
    }
}

const _: () = assert!(
    offset_of!(SnpTscInfoRequest, reserved) == 0x0
        && size_of::<SnpTscInfoRequest>() == TSC_INFO_REQ_SIZE
);

const _: () = assert!(
    offset_of!(SnpTscInfoResponse, status) == 0x0
        && offset_of!(SnpTscInfoResponse, reserved_04) == 0x4
        && offset_of!(SnpTscInfoResponse, tsc_scale) == 0x8
        && offset_of!(SnpTscInfoResponse, tsc_offset) == 0x10
        && offset_of!(SnpTscInfoResponse, tsc_factor) == 0x18
        && offset_of!(SnpTscInfoResponse, reserved_1c) == 0x1c
        && size_of::<SnpTscInfoResponse>() == TSC_INFO_REQ_SIZE
);
