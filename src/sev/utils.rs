// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PAGE_SIZE, PAGE_SIZE_2M};
use core::arch::asm;

#[derive(Debug)]
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

#[non_exhaustive]
pub enum RMPFlags {}

#[allow(dead_code)]
impl RMPFlags {
    pub const VMPL0     : u64 = 0;
    pub const VMPL1     : u64 = 1;
    pub const VMPL2     : u64 = 2;
    pub const VMPL3     : u64 = 3;
    pub const READ      : u64 = 1u64 << 8;
    pub const WRITE     : u64 = 1u64 << 9;
    pub const X_USER    : u64 = 1u64 << 10;
    pub const X_SUPER   : u64 = 1u64 << 11;
    pub const VMSA      : u64 = 1u64 << 16;

    pub const VMPL0_RWX : u64 = RMPFlags::VMPL0 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;
    pub const VMPL1_RWX : u64 = RMPFlags::VMPL1 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;
    pub const VMPL2_RWX : u64 = RMPFlags::VMPL2 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;
    pub const VMPL3_RWX : u64 = RMPFlags::VMPL3 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;

    pub const VMPL0_VMSA : u64 = RMPFlags::VMPL0 | RMPFlags::READ | RMPFlags::VMSA;
    pub const VMPL1_VMSA : u64 = RMPFlags::VMPL1 | RMPFlags::READ | RMPFlags::VMSA;
    pub const VMPL2_VMSA : u64 = RMPFlags::VMPL2 | RMPFlags::READ | RMPFlags::VMSA;
    pub const VMPL3_VMSA : u64 = RMPFlags::VMPL3 | RMPFlags::READ | RMPFlags::VMSA;
}

pub enum RMPAdjustError {
    FailInput,
    FailPermission,
    FailSizeMismatch,
    FailUnknown,
}

#[allow(dead_code)]
pub fn rmp_adjust(addr : VirtAddr, flags : u64, huge : bool) -> Result<(), RMPAdjustError> {
    let rcx : usize = if huge { PAGE_SIZE } else { PAGE_SIZE_2M };
    let rax : u64 = addr as u64;
    let rdx : u64 = flags as u64;
    let mut result : u64;

    unsafe {
        asm!(".byte 0xf3, 0x0f, 0x01, 0xfe",
                in("rax") rax,
                in("rcx") rcx,
                in("rdx") rdx,
                lateout("rax") result,
                options(att_syntax));
    }

    if result == 0 {
        Ok(())
    } else if result == 1 {
        Err(RMPAdjustError::FailInput)
    } else if result == 2 {
        Err(RMPAdjustError::FailPermission)
    } else if result == 6 {
        Err(RMPAdjustError::FailSizeMismatch)
    } else {
        Err(RMPAdjustError::FailUnknown)
    }
}
