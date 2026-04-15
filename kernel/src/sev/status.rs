// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::msr::read_msr;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use cpuarch::sev_status::MSR_SEV_STATUS;
use cpuarch::sev_status::SEVStatusFlags;

static SEV_FLAGS: ImmutAfterInitCell<SEVStatusFlags> = ImmutAfterInitCell::uninit();

fn read_sev_status() -> SEVStatusFlags {
    SEVStatusFlags::from_bits_truncate(read_msr(MSR_SEV_STATUS))
}

pub fn sev_flags() -> SEVStatusFlags {
    *SEV_FLAGS
}

pub fn sev_status_init() {
    let status: SEVStatusFlags = read_sev_status();
    SEV_FLAGS
        .init(status)
        .expect("Already initialized SEV flags");
}

pub fn vtom_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::VTOM)
}

pub fn sev_status_verify() {
    let required = SEVStatusFlags::SEV
        | SEVStatusFlags::SEV_ES
        | SEVStatusFlags::SEV_SNP
        | SEVStatusFlags::DBGSWP;
    let supported = SEVStatusFlags::VTOM
        | SEVStatusFlags::REST_INJ
        | SEVStatusFlags::PREV_HOST_IBS
        | SEVStatusFlags::BTB_ISOLATION
        | SEVStatusFlags::SMT_PROT;

    let status = sev_flags();
    let required_check = status & required;
    let not_supported_check = status & !(supported | required);

    if required_check != required {
        log::error!(
            "Required features not available: {}",
            required & !required_check
        );
        panic!("Required SEV features not available");
    }

    if !not_supported_check.is_empty() {
        log::error!("Unsupported features enabled: {not_supported_check}");
        panic!("Unsupported SEV features enabled");
    }
}
