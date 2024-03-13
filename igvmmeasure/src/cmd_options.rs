// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub struct CmdOptions {
    /// The filename of the IGVM file to measure
    #[arg()]
    pub igvm_file: String,

    /// Print verbose output
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Bare output only, consisting of just the digest as a hex string
    #[arg(short, long, default_value_t = false)]
    pub bare: bool,

    /// Platform to calculate the launch measurement for
    #[arg(short, long, value_enum, default_value_t = Platform::SevSnp)]
    pub platform: Platform,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Platform {
    /// Calculate the launch measurement for SEV-SNP
    SevSnp,
}
