// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use crate::sev::vmsa::VMPL_MAX;

use builtin_macros::*;
include!("types.verus.rs");

verus! {

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SHIFT_2M: usize = 21;
pub const PAGE_SHIFT_1G: usize = 30;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_SIZE_2M: usize = 1 << PAGE_SHIFT_2M;
pub const PAGE_SIZE_1G: usize = 1 << PAGE_SHIFT_1G;

}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Regular,
    Huge,
}

impl From<PageSize> for usize {
    fn from(psize: PageSize) -> Self {
        match psize {
            PageSize::Regular => PAGE_SIZE,
            PageSize::Huge => PAGE_SIZE_2M,
        }
    }
}

#[expect(clippy::identity_op)]
pub const SVSM_CS: u16 = 1 * 8;
pub const SVSM_DS: u16 = 2 * 8;
pub const SVSM_USER_CS: u16 = 3 * 8;
pub const SVSM_USER_DS: u16 = 4 * 8;
pub const SVSM_TSS: u16 = 6 * 8;

pub const SVSM_CS_ATTRIBUTES: u16 = 0xa09b;
pub const SVSM_DS_ATTRIBUTES: u16 = 0xc093;
pub const SVSM_TR_ATTRIBUTES: u16 = 0x89;

/// VMPL level the guest OS will be executed at.
/// Keep VMPL 1 for the SVSM and execute the OS at VMPL-2. This leaves VMPL-3
/// free for the OS to use in the future.
pub const GUEST_VMPL: usize = 2;

const _: () = assert!(GUEST_VMPL > 0 && GUEST_VMPL < VMPL_MAX);

pub const MAX_CPUS: usize = 512;

/// Length in byte which represents maximum 8 bytes(u64)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Bytes {
    #[default]
    Zero,
    One,
    Two,
    Four = 4,
    Eight = 8,
}

impl Bytes {
    pub fn mask(&self) -> u64 {
        match self {
            Bytes::Zero => 0,
            Bytes::One => (1 << 8) - 1,
            Bytes::Two => (1 << 16) - 1,
            Bytes::Four => (1 << 32) - 1,
            Bytes::Eight => u64::MAX,
        }
    }
}

impl TryFrom<usize> for Bytes {
    type Error = SvsmError;

    fn try_from(val: usize) -> Result<Bytes, Self::Error> {
        match val {
            0 => Ok(Bytes::Zero),
            1 => Ok(Bytes::One),
            2 => Ok(Bytes::Two),
            4 => Ok(Bytes::Four),
            8 => Ok(Bytes::Eight),
            _ => Err(SvsmError::InvalidBytes),
        }
    }
}
