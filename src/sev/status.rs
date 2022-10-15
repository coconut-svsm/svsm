// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::cpu::msr::{read_msr, SEV_STATUS};
use crate::print;

bitflags! {
    pub struct SEVStatusFlags: u64 {
        const SEV           = 1 << 0;
        const SEV_ES        = 1 << 1;
        const SEV_SNP       = 1 << 2;
        const VTOM          = 1 << 3;
        const REFLECT_VC    = 1 << 4;
        const REST_INJ      = 1 << 5;
        const ALT_INJ       = 1 << 6;
        const DBGSWP        = 1 << 7;
        const PREV_HOST_IBS = 1 << 8;
        const BTB_ISOLATION = 1 << 9;
        const SECURE_TSC    = 1 << 11;
        const VMSA_REG_PROT = 1 << 16;
    }
}

static mut SEV_FLAGS : SEVStatusFlags = SEVStatusFlags::empty();

fn read_sev_status() -> SEVStatusFlags {
    SEVStatusFlags::from_bits_truncate(read_msr(SEV_STATUS))
}

fn sev_flags() -> SEVStatusFlags {
    unsafe {SEV_FLAGS}
}

pub fn print_sev_status(prefix : &str, status : SEVStatusFlags) {

    print!("{}", prefix);

    if status.contains(SEVStatusFlags::SEV) {
        print!(" SEV");
    }

    if status.contains(SEVStatusFlags::SEV_ES) {
        print!(" SEV-ES");
    }

    if status.contains(SEVStatusFlags::SEV_SNP) {
        print!(" SEV-SNP");
    }

    if status.contains(SEVStatusFlags::VTOM) {
        print!(" VTOM");
    }
    
    if status.contains(SEVStatusFlags::REFLECT_VC) {
        print!(" REFLECT_VC");
    }
    
    if status.contains(SEVStatusFlags::REST_INJ) {
        print!(" RESTRICTED_INJECTION");
    }
    
    if status.contains(SEVStatusFlags::ALT_INJ) {
        print!(" ALTERNATE_INJECTION");
    }
    
    if status.contains(SEVStatusFlags::DBGSWP) {
        print!(" DEBUG_SWAP");
    }

    if status.contains(SEVStatusFlags::PREV_HOST_IBS) {
        print!(" PREVENT_HOST_IBS");
    }

    if status.contains(SEVStatusFlags::BTB_ISOLATION) {
        print!(" SNP_BTB_ISOLATION");
    }

    if status.contains(SEVStatusFlags::SECURE_TSC) {
        print!(" SECURE_TSC");
    }

    if status.contains(SEVStatusFlags::VMSA_REG_PROT) {
        print!(" VMSA_REG_PROT");
    }
    
    print!("\n");
}

pub fn sev_status_init() {
    let status : SEVStatusFlags = read_sev_status();
    unsafe { SEV_FLAGS = status; }
}

pub fn sev_es_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::SEV_ES)
}

pub fn sev_snp_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::SEV_SNP)
}

pub fn sev_status_verify() {
    let required = SEVStatusFlags::SEV | SEVStatusFlags::SEV_ES | SEVStatusFlags::SEV_SNP;
    let not_supported = SEVStatusFlags::VTOM | SEVStatusFlags::REFLECT_VC | SEVStatusFlags::REST_INJ |
                SEVStatusFlags::ALT_INJ | SEVStatusFlags::DBGSWP | SEVStatusFlags::PREV_HOST_IBS |
                SEVStatusFlags::BTB_ISOLATION | SEVStatusFlags::SECURE_TSC |
                SEVStatusFlags::VMSA_REG_PROT;

    let status = sev_flags();
    let required_check  = status & required;
    let supported_check = status & not_supported;

    if required_check != required {
        print_sev_status("Required features not available:", required & !required_check);
        panic!("Required SEV features not available");
    }

    if !supported_check.is_empty() {
        print_sev_status("Unsupported features enabled:", supported_check);
        panic!("Unsupported SEV features enabled");
    }
}

