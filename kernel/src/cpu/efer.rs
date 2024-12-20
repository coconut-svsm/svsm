// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::msr::{read_msr, write_msr, EFER};
use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct EFERFlags: u64 {
        const SCE   = 1 << 0;  // System Call Extensions
        const LME   = 1 << 8;  // Long Mode Enable
        const LMA   = 1 << 10; // Long Mode Active
        const NXE   = 1 << 11; // No-Execute Enable
        const SVME  = 1 << 12; // Secure Virtual Machine Enable
        const LMSLE = 1 << 13; // Long Mode Segment Limit Enable
        const FFXSR = 1 << 14; // Fast FXSAVE/FXRSTOR
        const TCE   = 1 << 15; // Translation Cache Extension
        const MCOMMIT   = 1 << 17; // Enable MCOMMIT instruction
        const INTWB = 1 << 18; // Interruptible WBINVD/WBNOINVD enable
        const UAIE  = 1 << 20; // Upper Address Ignore Enable
    }
}

pub fn read_efer() -> EFERFlags {
    EFERFlags::from_bits_truncate(read_msr(EFER))
}

pub fn write_efer(efer: EFERFlags) {
    let val = efer.bits();
    write_msr(EFER, val);
}

impl From<usize> for EFERFlags {
    fn from(bits: usize) -> Self {
        EFERFlags::from_bits_truncate(bits as u64)
    }
}
