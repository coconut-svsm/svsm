// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use super::features::cpu_has_nx;
use super::msr::{read_msr, write_msr, EFER};
use bitflags::bitflags;

bitflags! {
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

pub fn efer_init() {
    let mut efer = read_efer();

    if cpu_has_nx() {
        efer.insert(EFERFlags::NXE);
    }

    write_efer(efer);
}
