// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use bitfield_struct::bitfield;
use core::{ffi::CStr, mem};
use zerocopy::{Immutable, IntoBytes};

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
