// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::sync::Arc;
use bitfield_struct::bitfield;
use core::{ffi::CStr, fmt::Debug, mem};
use zerocopy::{Immutable, IntoBytes};

use crate::{address::PhysAddr, protocols::errors::SvsmReqError};

pub const OMP_NAME_LEN: usize = 120;
pub const OMP_IDENTIFIER_LEN: usize = OMP_NAME_LEN * 2;
pub const OMP_SOURCE_SIZE: usize = 128;

#[bitfield(u32)]
#[derive(IntoBytes, Immutable)]
/// Flags for an OMP source.
struct OmpSourceFlags {
    writable: bool,
    #[bits(31)]
    _rsvd_31_1: u32,
}

#[repr(u16)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of data the OMP source contains.
pub enum OmpSourceType {
    Object = 0,
    Bytes = 1,
    SInteger8Bit = 2,
    SInteger16Bit = 3,
    SInteger32Bit = 4,
    SInteger64Bit = 5,
}

/// OMP source details structure.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OmpSourceInfo {
    /// Source flags.
    flags: OmpSourceFlags,
    /// Type of the source.
    kind: OmpSourceType,
    /// Reserved field
    _rsvd: u16,
    /// Name of the source encoded as UTF-8.
    name: [u8; OMP_NAME_LEN],
}

impl OmpSourceInfo {
    pub fn new(writable: bool, name: &str, kind: OmpSourceType) -> Self {
        let mut name_bytes = [0u8; OMP_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len();

        if len == 0 || len >= OMP_NAME_LEN {
            // Failure if the length is greater than that value as we want
            // a null terminated string.
            panic!("Name length must not be zero nor exceed {OMP_NAME_LEN} bytes");
        }

        if bytes.contains(&b'/') || bytes.contains(&b'\0') {
            panic!("Name must not contain the '/' or null characters");
        }

        name_bytes[..len].copy_from_slice(bytes);

        Self {
            kind,
            flags: OmpSourceFlags::new().with_writable(writable),
            _rsvd: 0,
            name: name_bytes,
        }
    }

    pub fn new_object(name: &str) -> Self {
        Self::new(false, name, OmpSourceType::Object)
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
            OmpSourceType::Bytes => 1,
            OmpSourceType::SInteger8Bit => 1,
            OmpSourceType::SInteger16Bit => 2,
            OmpSourceType::SInteger32Bit => 4,
            OmpSourceType::SInteger64Bit => 8,
            OmpSourceType::Object => return false,
        };

        offset.is_multiple_of(type_size) && size.is_multiple_of(type_size)
    }
}

const _: () = assert!(
    mem::offset_of!(OmpSourceInfo, flags) == 0x00
        && mem::offset_of!(OmpSourceInfo, kind) == 0x04
        && mem::offset_of!(OmpSourceInfo, _rsvd) == 0x06
        && mem::offset_of!(OmpSourceInfo, name) == 0x08
        && mem::size_of::<OmpSourceInfo>() == OMP_SOURCE_SIZE
);

/// Callback type to use when iterating over each OMP source of an OMP object.
/// The callback should return `Ok(true)` to continue iteration.
/// `Ok(false)` or `Err(SvsmReqError)` stop the iteration.
pub type OmpSourceCallback<'a> =
    &'a mut dyn FnMut(&Arc<dyn OmpSource>) -> Result<bool, SvsmReqError>;

/// Operations required for an OMP object
pub trait OmpObject: Debug + Send + Sync {
    fn get_name(&self) -> &str;
    fn get_info(&self) -> &OmpSourceInfo;
    fn get_source(&self, name: &str) -> Option<Arc<dyn OmpSource>>;
    /// Applies `f` to every source until `f` returns `Ok(false)` or an error.
    /// In the latter case, the error is returned.
    fn for_each_source(&self, f: OmpSourceCallback<'_>) -> Result<(), SvsmReqError>;
    fn get_source_count(&self) -> usize;
}

/// Operations required for an OMP source
pub trait OmpSource: Debug + Send + Sync {
    /// Reads `size` bytes from the `gpa` into the local source at the specified `offset`.
    fn read_from_guest(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    /// Writes `size` bytes from the local source at the specified `offset` to the `gpa`.
    fn write_to_guest(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn get_info(&self) -> &OmpSourceInfo;
}
