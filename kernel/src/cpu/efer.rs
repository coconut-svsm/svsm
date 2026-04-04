// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::msr::read_msr;
use super::msr::write_msr;
use cpuarch::x86::EFERFlags;
use cpuarch::x86::MSR_EFER;

pub fn read_efer() -> EFERFlags {
    EFERFlags::from_bits_truncate(read_msr(MSR_EFER))
}

/// # Safety
///
/// The caller should ensure that the new value written to EFER MSR doesn't
/// break memory safety.
pub unsafe fn write_efer(efer: EFERFlags) {
    let val = efer.bits();
    // SAFETY: requirements should be verified by the caller.
    unsafe {
        write_msr(MSR_EFER, val);
    }
}
