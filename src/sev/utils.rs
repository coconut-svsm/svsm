// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr};
use core::arch::asm;

#[derive(Debug)]
pub struct PValidateError {
    pub error_code: u64,
    pub changed: bool,
}

impl PValidateError {
    pub fn new(code: u64, changed: bool) -> Self {
        PValidateError { error_code: code, changed: changed }
    }
}

pub fn pvalidate(vaddr: VirtAddr, huge_page: bool, valid: bool) -> Result<(), PValidateError> {
    let rax = vaddr;
    let rcx = {
        if huge_page {
            1
        } else {
            0
        }
    };
    let rdx = {
        if valid {
            1
        } else {
            0
        }
    };
    let ret: u64;
    let cf: u64;

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

    let changed : bool = cf == 0;

    if ret == 0 && changed {
        Ok(())
    } else {
        Err(PValidateError::new(ret, changed))
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
    pub const VMPL0: u64 = 0;
    pub const VMPL1: u64 = 1;
    pub const VMPL2: u64 = 2;
    pub const VMPL3: u64 = 3;
    pub const READ: u64 = 1u64 << 8;
    pub const WRITE: u64 = 1u64 << 9;
    pub const X_USER: u64 = 1u64 << 10;
    pub const X_SUPER: u64 = 1u64 << 11;
    pub const VMSA: u64 = 1u64 << 16;

    pub const VMPL0_NONE: u64 = RMPFlags::VMPL0;
    pub const VMPL1_NONE: u64 = RMPFlags::VMPL1;
    pub const VMPL2_NONE: u64 = RMPFlags::VMPL2;
    pub const VMPL3_NONE: u64 = RMPFlags::VMPL3;

    pub const VMPL0_RWX: u64 =
        RMPFlags::VMPL0 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;
    pub const VMPL1_RWX: u64 =
        RMPFlags::VMPL1 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;
    pub const VMPL2_RWX: u64 =
        RMPFlags::VMPL2 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;
    pub const VMPL3_RWX: u64 =
        RMPFlags::VMPL3 | RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;

    pub const VMPL0_VMSA: u64 = RMPFlags::VMPL0 | RMPFlags::READ | RMPFlags::VMSA;
    pub const VMPL1_VMSA: u64 = RMPFlags::VMPL1 | RMPFlags::READ | RMPFlags::VMSA;
    pub const VMPL2_VMSA: u64 = RMPFlags::VMPL2 | RMPFlags::READ | RMPFlags::VMSA;
    pub const VMPL3_VMSA: u64 = RMPFlags::VMPL3 | RMPFlags::READ | RMPFlags::VMSA;
}

pub enum RMPAdjustError {
    FailInput,
    FailPermission,
    FailSizeMismatch,
    FailUnknown,
}

pub fn rmp_adjust(addr: VirtAddr, flags: u64, huge: bool) -> Result<(), RMPAdjustError> {
    let rcx: usize = if huge { 1 } else { 0 };
    let rax: u64 = addr as u64;
    let rdx: u64 = flags as u64;
    let mut result: u64;

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

pub fn rmp_adjust_report(addr: VirtAddr, flags: u64, huge: bool) -> Result<(),()> {
    if let Err(_) = rmp_adjust(addr, flags, huge) {
        log::error!("RMPADJUST failed for addr {:#018x}", addr);
        return Err(());
    }

    Ok(())
}
