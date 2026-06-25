// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::sync::Arc;
use bitfield_struct::bitfield;
use core::{ffi::CStr, fmt::Debug, mem, slice::Iter};
use zerocopy::{Immutable, IntoBytes};

use crate::{address::PhysAddr, protocols::errors::SvsmReqError};

pub const OCP_NAME_LEN: usize = 120;
pub const OCP_IDENTIFIER_LEN: usize = OCP_NAME_LEN * 2;
pub const OCP_SOURCE_SIZE: usize = 128;

#[bitfield(u32)]
#[derive(IntoBytes, Immutable)]
/// Flags for an OCP source.
struct OcpSourceFlags {
    writable: bool,
    #[bits(31)]
    _rsvd_31_1: u32,
}

#[repr(u16)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of data the OCP source contains.
pub enum OcpSourceType {
    Object = 0,
    Bytes = 1,
    SInteger8Bit = 2,
    SInteger16Bit = 3,
    SInteger32Bit = 4,
    SInteger64Bit = 5,
}

/// OCP source details structure.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpSourceInfo {
    /// Source flags.
    flags: OcpSourceFlags,
    /// Type of the source.
    kind: OcpSourceType,
    /// Reserved field
    _rsvd: u16,
    /// Name of the source encoded as UTF-8.
    name: [u8; OCP_NAME_LEN],
}

impl OcpSourceInfo {
    pub fn new(writable: bool, name: &str, kind: OcpSourceType) -> Self {
        let mut name_bytes = [0u8; OCP_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len();

        if len == 0 || len >= OCP_NAME_LEN {
            // Failure if the length is greater than that value as we want
            // a null terminated string.
            panic!("Name length must not be zero nor exceed {OCP_NAME_LEN} bytes");
        }

        if bytes.contains(&b'/') || bytes.contains(&b'\0') {
            panic!("Name must not contain the '/' or null characters");
        }

        name_bytes[..len].copy_from_slice(bytes);

        Self {
            kind,
            flags: OcpSourceFlags::new().with_writable(writable),
            _rsvd: 0,
            name: name_bytes,
        }
    }

    pub fn new_object(name: &str) -> Self {
        Self::new(false, name, OcpSourceType::Object)
    }

    pub fn get_name(&self) -> &str {
        let name = CStr::from_bytes_until_nul(&self.name).unwrap();
        name.to_str().unwrap()
    }

    pub fn is_writable(&self) -> bool {
        self.flags.writable()
    }

    pub fn is_valid_access(&self, offset: u32, size: u32) -> bool {
        let type_size = match self.kind {
            OcpSourceType::Bytes => 1,
            OcpSourceType::SInteger8Bit => 1,
            OcpSourceType::SInteger16Bit => 2,
            OcpSourceType::SInteger32Bit => 4,
            OcpSourceType::SInteger64Bit => 8,
            OcpSourceType::Object => {
                return false;
            }
        };

        offset.is_multiple_of(type_size) && size.is_multiple_of(type_size)
    }
}

const _: () = assert!(
    mem::offset_of!(OcpSourceInfo, flags) == 0x00
        && mem::offset_of!(OcpSourceInfo, kind) == 0x04
        && mem::offset_of!(OcpSourceInfo, _rsvd) == 0x06
        && mem::offset_of!(OcpSourceInfo, name) == 0x08
        && mem::size_of::<OcpSourceInfo>() == OCP_SOURCE_SIZE
);

/// Operations required for an OCP object
pub trait OcpObject: Debug + Send + Sync {
    fn get_name(&self) -> &str;
    fn get_info(&self) -> &OcpSourceInfo;
    fn get_source(&self, name: &str) -> Option<Arc<dyn OcpSource>>;
    // todo: change return type of get_sources
    fn get_sources(&self) -> Iter<'_, Arc<dyn OcpSource>>;
    fn get_source_count(&self) -> usize;
}

/// Operations required for an OCP source
pub trait OcpSource: Debug + Send + Sync {
    fn read(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn write(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn get_info(&self) -> &OcpSourceInfo;
}
