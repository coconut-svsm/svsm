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

    /// Check that the IGVM file conforms to QEMU/KVM restrictions
    #[arg(short, long, default_value_t = false)]
    pub check_kvm: bool,

    /// Platform to calculate the launch measurement for
    #[arg(short, long, value_enum, default_value_t = Platform::SevSnp)]
    pub platform: Platform,

    /// Determine how to pages that contain only zeroes in the IGVM file.
    ///
    /// When true, zero pages are measured using the native zero page type
    /// if the underlying platform supports it.
    ///
    /// When false, the page is measured as a normal page containing all zeros.
    #[arg(short, long, default_value_t = false)]
    pub native_zero: bool,

    /// If an ID block is present within the IGVM file then by default an
    /// error will be generated if the expected measurement differs from
    /// the calculated measurement.
    ///
    /// If this option is set then the expected measurement in the ID block
    /// is ignored.
    #[arg(short, long, default_value_t = false)]
    pub ignore_idblock: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Platform {
    /// Calculate the launch measurement for SEV-SNP
    SevSnp,
}
