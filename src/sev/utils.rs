// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr};
use core::arch::asm;

pub enum PValidateError {
    FailInput,
    FailSizeMismatch,
    FailUnknown,
    FailNotChanged,
}

pub fn pvalidate(vaddr : VirtAddr, huge_page: bool, valid : bool) -> Result<(),PValidateError> {
    let rax = vaddr;
    let rcx = { if huge_page { 1 } else { 0 } };
    let rdx = { if valid { 1 } else { 0 } };
    let ret : u64;
    let cf : u64;

    unsafe {
        asm!(".byte 0xf2, 0x0f, 0x01, 0xff",
             "xorq %rcx, %rcx",
             "jnc 1f",
             "incq %rcx",
             "1:",
             in("rax")  rax,
             in("rcx")  rcx,
             in("rdx")  rdx,
             lateout("rax") ret,
             lateout("rcx") cf,
             options(att_syntax));
    }

    if cf == 1 {
        return Err(PValidateError::FailNotChanged);
    }

    if ret == 0 {
        Ok(())
    } else if ret == 1 {
        Err(PValidateError::FailInput)
    } else if ret == 6 {
        Err(PValidateError::FailSizeMismatch)
    } else {
        Err(PValidateError::FailUnknown)
    }
}

pub fn raw_vmgexit() {
    unsafe {
        asm!("rep; vmmcall", options(att_syntax));
    }
}

