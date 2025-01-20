// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]

use core::fmt;

#[allow(dead_code)]
#[derive(Debug)]
enum ReleaseType {
    /// Development Release
    Development,
    /// Stable Release Candidate
    Candidate(u32),
    /// Stable Release
    Stable(u32),
}

#[derive(Debug)]
pub struct SvsmVersion {
    year: u32,
    month: u32,
    release_type: ReleaseType,
}

impl fmt::Display for SvsmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.release_type {
            ReleaseType::Development => {
                write!(f, "{}.{:#02}-devel", self.year, self.month)
            }
            ReleaseType::Candidate(counter) => {
                write!(f, "{}.{:#02}-rc{}", self.year, self.month, counter)
            }
            ReleaseType::Stable(counter) => {
                write!(f, "{}.{:#02}.{}", self.year, self.month, counter)
            }
        }
    }
}

const VERSION_YEAR: u32 = 2025;
const VERSION_MONTH: u32 = 1;
#[allow(dead_code)]
const VERSION_COUNTER: u32 = 0;

pub static COCONUT_VERSION: SvsmVersion = SvsmVersion {
    year: VERSION_YEAR,
    month: VERSION_MONTH,
    release_type: ReleaseType::Development,
};
