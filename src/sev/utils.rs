// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::is_aligned;
use core::arch::asm;

const PV_ERR_FAIL_SIZE_MISMATCH: u64 = 6;

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

fn pvalidate_range_4k(start: VirtAddr, end: VirtAddr, valid: bool) -> Result<(), PValidateError> {
    let mut addr = start;

    while addr < end {
        pvalidate(addr, false, valid)?;
        addr += PAGE_SIZE;
    }

    Ok(())
}

pub fn pvalidate_range(start: VirtAddr, end: VirtAddr, valid: bool) -> Result<(), PValidateError> {
    let mut addr = start;

    while addr < end {
        if is_aligned(addr, PAGE_SIZE_2M) && (addr + PAGE_SIZE_2M) <= end {
            if let Err(e) = pvalidate(addr, true, valid) {
                if e.error_code == PV_ERR_FAIL_SIZE_MISMATCH {
                    pvalidate_range_4k(addr, addr + PAGE_SIZE_2M, valid)?;
                } else {
                    return Err(e);
                }
            }
            addr += PAGE_SIZE_2M;
        } else {
            pvalidate(addr, false, valid)?;
            addr += PAGE_SIZE;
        }
    }

    Ok(())
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
    pub const BIT_VMSA: u64 = 1u64 << 16;

    pub const NONE: u64 = 0;
    pub const RWX: u64 = RMPFlags::READ | RMPFlags::WRITE | RMPFlags::X_USER | RMPFlags::X_SUPER;

    pub const VMSA: u64 = RMPFlags::READ | RMPFlags::BIT_VMSA;
}

pub fn rmp_adjust(addr: VirtAddr, flags: u64, huge: bool) -> Result<(), u64> {
    let rcx: usize = if huge { 1 } else { 0 };
    let rax: u64 = addr as u64;
    let rdx: u64 = flags as u64;
    let mut result: u64;
    let mut ex: u64;

    unsafe {
        asm!("1: .byte 0xf3, 0x0f, 0x01, 0xfe
                 xorq %rcx, %rcx
              2:
              .pushsection \"__exception_table\",\"a\"
              .balign 16
              .quad (1b)
              .quad (2b)
              .popsection",
                in("rax") rax,
                in("rcx") rcx,
                in("rdx") rdx,
                lateout("rax") result,
                lateout("rcx") ex,
                options(att_syntax));
    }

    if result == 0 && ex == 0 {
        // RMPADJUST completed successfully
        Ok(())
    } else if ex == 0 {
        // RMPADJUST instruction completed with failure
        Err(result)
    } else {
        // Report exceptions on RMPADJUST just as FailInput
        Err(1u64)
    }
}

fn rmpadjust_adjusted_error(vaddr: VirtAddr, flags: u64, huge: bool) -> Result<(),u64> {
    if let Err(code) = rmp_adjust(vaddr, flags, huge) {
        let ret_code = if code < 0x10 { code } else { 0x11 };
        Err(ret_code)
    } else {
        Ok(())
    }
}

pub fn rmp_revoke_guest_access(vaddr: VirtAddr, huge: bool) -> Result<(),u64>
{
    rmpadjust_adjusted_error(vaddr, RMPFlags::VMPL1 | RMPFlags::NONE, huge)?;
    rmpadjust_adjusted_error(vaddr, RMPFlags::VMPL2 | RMPFlags::NONE, huge)?;
    rmpadjust_adjusted_error(vaddr, RMPFlags::VMPL3 | RMPFlags::NONE, huge)?;

    Ok(())
}

pub fn rmp_grant_guest_access(vaddr: VirtAddr, huge: bool) -> Result<(),u64>
{
    rmpadjust_adjusted_error(vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, huge)?;

    Ok(())
}

pub fn rmp_set_guest_vmsa(vaddr: VirtAddr) -> Result<(), u64> {
    rmp_revoke_guest_access(vaddr, false)?;
    rmpadjust_adjusted_error(vaddr, RMPFlags::VMPL1 | RMPFlags::VMSA, false)?;

    Ok(())
}

pub fn rmp_clear_guest_vmsa(vaddr: VirtAddr) -> Result<(), u64> {
    rmp_revoke_guest_access(vaddr, false)?;
    rmp_grant_guest_access(vaddr, false)?;

    Ok(())
}

