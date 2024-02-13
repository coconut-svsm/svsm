// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::msr::{read_msr, SEV_STATUS};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use bitflags::bitflags;
use core::fmt::{self, Write};

bitflags! {
    #[derive(Copy, Clone, PartialEq, Eq)]
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
        const VMPL_SSS      = 1 << 10;
        const SECURE_TSC    = 1 << 11;
        const VMSA_REG_PROT = 1 << 16;
        const SMT_PROT      = 1 << 17;
    }
}

impl fmt::Display for SEVStatusFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        if self.contains(SEVStatusFlags::SEV) {
            f.write_str("SEV")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::SEV_ES) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("SEV-ES")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::SEV_SNP) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("SEV-SNP")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::VTOM) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("VTOM")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::REFLECT_VC) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("REFLECT_VC")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::REST_INJ) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("RESTRICTED_INJECTION")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::ALT_INJ) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("ALTERNATE_INJECTION")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::DBGSWP) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("DEBUG_SWAP")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::PREV_HOST_IBS) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("PREVENT_HOST_IBS")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::BTB_ISOLATION) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("SNP_BTB_ISOLATION")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::SECURE_TSC) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("SECURE_TSC")?;
            first = false;
        }

        if self.contains(SEVStatusFlags::VMSA_REG_PROT) {
            if !first {
                f.write_char(' ')?;
            }
            f.write_str("VMSA_REG_PROT")?;
        }

        Ok(())
    }
}

static SEV_FLAGS: ImmutAfterInitCell<SEVStatusFlags> = ImmutAfterInitCell::uninit();

fn read_sev_status() -> SEVStatusFlags {
    SEVStatusFlags::from_bits_truncate(read_msr(SEV_STATUS))
}

pub fn sev_flags() -> SEVStatusFlags {
    *SEV_FLAGS
}

pub fn sev_status_init() {
    let status: SEVStatusFlags = read_sev_status();
    SEV_FLAGS
        .init(&status)
        .expect("Already initialized SEV flags");
}

pub fn sev_es_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::SEV_ES)
}

pub fn sev_snp_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::SEV_SNP)
}

pub fn vtom_enabled() -> bool {
    sev_flags().contains(SEVStatusFlags::VTOM)
}

pub fn sev_status_verify() {
    let required = SEVStatusFlags::SEV | SEVStatusFlags::SEV_ES | SEVStatusFlags::SEV_SNP;
    let supported = SEVStatusFlags::DBGSWP
        | SEVStatusFlags::VTOM
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
        log::error!("Unsupported features enabled: {}", not_supported_check);
        panic!("Unsupported SEV features enabled");
    }
}

impl SEVStatusFlags {
    pub fn from_sev_features(sev_features: u64) -> Self {
        SEVStatusFlags::from_bits(sev_features << 2).unwrap()
    }

    pub fn as_sev_features(&self) -> u64 {
        let sev_features = self.bits();
        sev_features >> 2
    }
}
