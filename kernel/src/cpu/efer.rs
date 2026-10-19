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

/// Disables the `syscall` instruction by clearing `EFER.SCE`.
///
/// The SVSM handles system calls from user mode in the #UD handler, which
/// relies on the `syscall` instruction raising #UD.
pub fn disable_syscall_insn() {
    let efer = read_efer();
    if efer.contains(EFERFlags::SCE) {
        log::warn!("EFER.SCE is set, clearing it");
        // SAFETY: SCE only enables the syscall instruction. Clearing it
        // makes the instruction raise #UD and cannot break memory safety.
        unsafe {
            write_efer(efer.difference(EFERFlags::SCE));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_syscall_insn_disabled() {
        assert!(!read_efer().contains(EFERFlags::SCE));
    }
}
