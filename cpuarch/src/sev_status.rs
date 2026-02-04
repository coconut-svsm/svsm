// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use bitflags::bitflags;
use core::fmt;
use core::fmt::Write;

pub const MSR_SEV_STATUS: u32 = 0xC001_0131;

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

impl SEVStatusFlags {
    pub fn from_sev_features(sev_features: u64) -> Self {
        SEVStatusFlags::from_bits(sev_features << 2).unwrap()
    }

    pub fn as_sev_features(&self) -> u64 {
        let sev_features = self.bits();
        sev_features >> 2
    }
}
