// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

//! OCP protocol implementation (SVSM draft spec).

use crate::{address::PhysAddr, protocols::errors::SvsmReqError};
use bitfield_struct::bitfield;
use core::{fmt::Debug, mem};
use zerocopy::{Immutable, IntoBytes};

const OCP_SOURCE_NAME_LEN: usize = 112;
const OCP_SOURCE_ENTRY_SIZE: usize = 128;
const OCP_SOURCE_DETAILS_SIZE: usize = 12;

#[bitfield(u32)]
#[derive(IntoBytes, Immutable)]
struct OcpSourceFlags {
    writable: bool,
    #[bits(31)]
    _rsvd_31_1: u32,
}

#[repr(u32)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of data the OCP source contains.
pub enum OcpSourceType {
    StaticString = 0,
}

/// OCP source entry structure.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpSource {
    /// Super index of the source
    sup_index: u32,
    /// Sub index of the source
    sub_index: u32,
    /// Type of the source.
    kind: OcpSourceType,
    /// Source flags.
    flags: OcpSourceFlags,
    /// Name of the source encoded as UTF-8.
    name: [u8; OCP_SOURCE_NAME_LEN],
}

impl OcpSource {
    pub fn new(
        sup_index: u32,
        sub_index: u32,
        writable: bool,
        name: &str,
        kind: OcpSourceType,
    ) -> Self {
        let mut name_bytes = [0u8; OCP_SOURCE_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len();

        if len == 0 || len >= OCP_SOURCE_NAME_LEN {
            // Failure if the length is greater than that value as we want
            // a null terminated string.
            panic!("Name length must not be zero nor exceed {OCP_SOURCE_NAME_LEN} bytes");
        }

        name_bytes[..len].copy_from_slice(bytes);

        Self {
            sup_index,
            sub_index,
            kind,
            flags: OcpSourceFlags::new().with_writable(writable),
            name: name_bytes,
        }
    }
}

const _: () = assert!(
    mem::offset_of!(OcpSource, sup_index) == 0x00
        && mem::offset_of!(OcpSource, sub_index) == 0x04
        && mem::offset_of!(OcpSource, kind) == 0x08
        && mem::offset_of!(OcpSource, flags) == 0x0C
        && mem::offset_of!(OcpSource, name) == 0x10
        && mem::size_of::<OcpSource>() == OCP_SOURCE_ENTRY_SIZE
);

#[repr(u32)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of objects the SVSM contains.
pub enum OcpObjectType {
    Svsm = 0,
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpObjectDetails {
    category: OcpObjectType,
    index: u32,
    count: u32,
}

/// Operations required for an OCP object
pub trait OcpObjectOperations: Debug + Send + Sync {
    fn read(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn write(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn get_object_details(&self) -> &OcpObjectDetails;
    fn get_object_sources(&self) -> &[OcpSource];
}
