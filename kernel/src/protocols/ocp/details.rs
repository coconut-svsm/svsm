// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use bitfield_struct::bitfield;
use core::mem;
use zerocopy::{Immutable, IntoBytes};

const OCP_SOURCE_NAME_LEN: usize = 112;
pub const OCP_SOURCE_DETAILS_SIZE: usize = 128;
pub const OCP_OBJECT_DETAILS_SIZE: usize = 12;

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
    Integer = 1,
    String = 2,
}

/// OCP source details structure.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpSourceDetails {
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

impl OcpSourceDetails {
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

#[repr(u32)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of objects the SVSM contains.
pub enum OcpObjectType {
    Svsm = 0,
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpObjectDetails {
    sup_index: u32,
    category: OcpObjectType,
    count: u32,
}

impl OcpObjectDetails {
    pub fn new(category: OcpObjectType, sup_index: u32) -> Self {
        OcpObjectDetails {
            sup_index,
            category,
            count: 0,
        }
    }

    pub fn increase_count(&mut self) {
        // todo: mut shouldn't be here
        self.count += 1;
    }
}

const _: () = assert!(
    mem::offset_of!(OcpSourceDetails, sup_index) == 0x00
        && mem::offset_of!(OcpSourceDetails, sub_index) == 0x04
        && mem::offset_of!(OcpSourceDetails, kind) == 0x08
        && mem::offset_of!(OcpSourceDetails, flags) == 0x0C
        && mem::offset_of!(OcpSourceDetails, name) == 0x10
        && mem::size_of::<OcpSourceDetails>() == OCP_SOURCE_DETAILS_SIZE
);

const _: () = assert!(
    mem::offset_of!(OcpObjectDetails, sup_index) == 0x00
        && mem::offset_of!(OcpObjectDetails, category) == 0x04
        && mem::offset_of!(OcpObjectDetails, count) == 0x08
        && mem::size_of::<OcpObjectDetails>() == OCP_OBJECT_DETAILS_SIZE
);
