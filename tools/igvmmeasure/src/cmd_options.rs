// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
pub struct CmdOptions {
    /// The filename of the input IGVM file to measure
    #[arg()]
    pub input: String,

    /// Print verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Check that the IGVM file conforms to QEMU/KVM restrictions
    #[arg(short, long)]
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
    #[arg(short, long)]
    pub native_zero: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Measure the input file and print the measurement to the console.
    Measure {
        /// If an ID block is present within the IGVM file then by default an
        /// error will be generated if the expected measurement differs from
        /// the calculated measurement.
        ///
        /// If this option is set then the expected measurement in the ID block
        /// is ignored.
        #[arg(short, long)]
        ignore_idblock: bool,

        /// Bare output only, consisting of just the digest as a hex string
        #[arg(short, long)]
        bare: bool,
    },
    /// Measure the input file and generate a new output file containing a
    /// signature suitable for the target platform. For SEV-SNP this generates
    /// an IGVM_VHT_SNP_ID_BLOCK directive in the output file.
    Sign {
        /// Output filename of the signed IGVM file that will be created.
        #[arg(long)]
        output: String,

        /// Filename of the private key that is used to sign the contents of
        /// the ID block. For SEV-SNP platforms, this should be an ECDSA P-384
        /// key. You can create a key using:
        ///
        /// $ openssl ecparam -name secp384r1 -genkey -noout -out
        #[arg(long)]
        id_key: String,

        /// Filename of the author private key that is used to sign the public
        /// part of the id_key. For SEV-SNP platforms, this should be an ECDSA
        /// P-384 key. You can create a key using:
        ///
        /// $ openssl ecparam -name secp384r1 -genkey -noout -out
        ///
        /// The author key is option. See the SEV-SNP documentation for more
        /// information.
        #[arg(long)]
        author_key: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Platform {
    /// Calculate the launch measurement for SEV
    Sev,
    /// Calculate the launch measurement for SEV-ES
    SevEs,
    /// Calculate the launch measurement for SEV-SNP
    SevSnp,
}
