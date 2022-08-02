// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::cpu::msr::{read_msr, write_msr, SEV_GHCB};
use crate::types::{PhysAddr, VirtAddr};

use super::utils::raw_vmgexit;

#[non_exhaustive]
enum GHCBMsr {}

impl GHCBMsr {
    pub const SNP_REG_GHCB_GPA_REQ  : u64 = 0x12;
    pub const SNP_REG_GHCB_GPA_RESP : u64 = 0x13;
    pub const SNP_STATE_CHANGE_REQ  : u64 = 0x14;
    pub const SNP_STATE_CHANGE_RESP : u64 = 0x15;
    pub const TERM_REQ      : u64 = 0x100;
}

pub fn register_ghcb_gpa_msr(addr: VirtAddr) -> Result<(),()> {
    let mut info : u64 = addr as u64;

    info |= GHCBMsr::SNP_REG_GHCB_GPA_REQ;
    write_msr(SEV_GHCB, info);
    raw_vmgexit();
    info = read_msr(SEV_GHCB);

    if (info & 0xfffu64) != GHCBMsr::SNP_REG_GHCB_GPA_RESP {
        return Err(());
    }

    if (info & !0xfffu64) == (addr as u64) {
        Ok(())
    } else {
        Err(())
    }
}

fn set_page_valid_status_msr(addr : PhysAddr, valid : bool) -> Result<(),()> {
    let mut info : u64 = (addr as u64) & 0x000f_ffff_ffff_f000;

    if valid {
        info |= 1u64 << 52;
    } else {
        info |= 2u64 << 52;
    }

    info |= GHCBMsr::SNP_STATE_CHANGE_REQ;
    write_msr(SEV_GHCB, info);
    raw_vmgexit();
    let response = read_msr(SEV_GHCB);

    if (response & !0xfffu64) != 0 {
        return Err(());
    }

    if (response & 0xfffu64) != GHCBMsr::SNP_STATE_CHANGE_RESP {
        return Err(());
    }

    Ok(())
}

pub fn validate_page_msr(addr: PhysAddr) -> Result<(),()> {
    set_page_valid_status_msr(addr, true)
}

pub fn invalidate_page_msr(addr: PhysAddr) -> Result<(),()> {
    set_page_valid_status_msr(addr, false)
}

pub fn request_termination_msr() {
    let info : u64 = GHCBMsr::TERM_REQ;

    write_msr(SEV_GHCB, info);
    raw_vmgexit();
    loop {};
}

