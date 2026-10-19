// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Advanced Micro Devices, Inc
//
// Author: Mahmoud Nagy Adam <madam@amd.com>

//! Tests for entering the kernel with the `syscall` instruction.

use core::arch::asm;
use userlib::{SYS_CAPABILITIES, SysCallError};

/// A number that is not a system call.
const SYS_INVALID: u64 = 0xdead_beef;

/// Issues a system call with one argument using the `syscall` instruction.
fn syscall_insn(nr: u64, arg: u64) -> u64 {
    let ret: u64;
    // SAFETY: only used for system calls that do not access user memory.
    // The registers clobbered by the instruction are declared.
    unsafe {
        asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") arg,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Checks that a system call issued with the `syscall` instruction is
/// dispatched and returns its result. The capabilities call has no side
/// effects, and the first index after the last capability is an error.
#[test]
#[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
fn test_syscall_insn_dispatch() {
    // Index 0 returns the number of capabilities, which follow it.
    let count = syscall_insn(SYS_CAPABILITIES, 0);
    assert!(count > 0);

    // Every valid index succeeds. Errors are negative values.
    for index in 1..=count {
        let ret = syscall_insn(SYS_CAPABILITIES, index) as i64;
        assert!(ret >= 0, "index {index} failed with {ret}");
    }

    // The first index after the last capability is invalid.
    assert_eq!(
        syscall_insn(SYS_CAPABILITIES, count + 1) as i64,
        SysCallError::ENOENT as i64
    );
}

/// Checks that the `syscall` instruction preserves the registers it does
/// not clobber, and that an unknown system call returns an error.
#[test]
#[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
fn test_syscall_insn_registers() {
    let ret: u64;
    let (rdi, rsi, rdx, r8, r9, r10): (u64, u64, u64, u64, u64, u64);

    // SAFETY: an invalid system call has no effect. Every register the
    // instruction or the kernel may change is declared.
    unsafe {
        asm!(
            "syscall",
            inout("rax") SYS_INVALID => ret,
            inout("rdi") 1u64 => rdi,
            inout("rsi") 2u64 => rsi,
            inout("rdx") 3u64 => rdx,
            inout("r8") 4u64 => r8,
            inout("r9") 5u64 => r9,
            inout("r10") 6u64 => r10,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }

    assert_eq!(ret as i64, SysCallError::EINVAL as i64);
    // All registers other than rax, rcx and r11 are preserved.
    assert_eq!((rdi, rsi, rdx, r8, r9, r10), (1, 2, 3, 4, 5, 6));
}
