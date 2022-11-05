// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::cpu::msr::{read_msr, SEV_STATUS};
use core::fmt::{self, Write};
use log;

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

impl fmt::Display for SEVStatusFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        if self.contains(SEVStatusFlags::SEV) {
            f.write_str("SEV")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::SEV_ES) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("SEV-ES")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::SEV_SNP) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("SEV-SNP")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::VTOM) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("VTOM")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::REFLECT_VC) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("REFLECT_VC")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::REST_INJ) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("RESTRICTED_INJECTION")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::ALT_INJ) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("ALTERNATE_INJECTION")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::DBGSWP) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("DEBUG_SWAP")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::PREV_HOST_IBS) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("PREVENT_HOST_IBS")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::BTB_ISOLATION) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("SNP_BTB_ISOLATION")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::SECURE_TSC) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("SECURE_TSC")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::VMSA_REG_PROT) {
            if first == false {
                f.write_char(' ')?;
            }
            f.write_str("VMSA_REG_PROT")?;
        }

        fmt::Result::Ok(())
    }
}

static mut SEV_FLAGS: SEVStatusFlags = SEVStatusFlags::empty();

fn read_sev_status() -> SEVStatusFlags {
    SEVStatusFlags::from_bits_truncate(read_msr(SEV_STATUS))
}

fn sev_flags() -> SEVStatusFlags {
    unsafe { SEV_FLAGS }
}

pub fn sev_status_init() {
    let status: SEVStatusFlags = read_sev_status();
    unsafe {
        SEV_FLAGS = status;
    }
}

pub fn sev_es_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::SEV_ES)
}

pub fn sev_snp_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::SEV_SNP)
}

pub fn sev_status_verify() {
    let required = SEVStatusFlags::SEV | SEVStatusFlags::SEV_ES | SEVStatusFlags::SEV_SNP;
    let not_supported = SEVStatusFlags::VTOM
        | SEVStatusFlags::REFLECT_VC
        | SEVStatusFlags::REST_INJ
        | SEVStatusFlags::ALT_INJ
        | SEVStatusFlags::DBGSWP
        | SEVStatusFlags::PREV_HOST_IBS
        | SEVStatusFlags::BTB_ISOLATION
        | SEVStatusFlags::SECURE_TSC
        | SEVStatusFlags::VMSA_REG_PROT;

    let status = sev_flags();
    let required_check = status & required;
    let supported_check = status & not_supported;

    if required_check != required {
        log::error!(
            "Required features not available: {}",
            required & !required_check
        );
        panic!("Required SEV features not available");
    }

    if !supported_check.is_empty() {
        log::error!("Unsupported features enabled: {}", supported_check);
        panic!("Unsupported SEV features enabled");
    }
}
