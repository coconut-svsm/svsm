// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>
#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, File};
use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};
use igvm::IgvmFile;
use igvm_defs::IgvmPlatformType;
use zerocopy::IntoBytes;

use igvmmeasure::id_block::SevIdBlockBuilder;
use igvmmeasure::igvm_measure::IgvmMeasure;
use igvmmeasure::utils::get_compatibility_mask;

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

fn main() -> Result<(), Box<dyn Error>> {
    let options = CmdOptions::parse();

    let igvm_buffer = fs::read(&options.input).inspect_err(|_| {
        eprintln!("Failed to open firmware file {}", options.input);
    })?;
    let igvm = IgvmFile::new_from_binary(igvm_buffer.as_bytes(), None)?;
    let platform = match options.platform {
        Platform::Sev => IgvmPlatformType::SEV,
        Platform::SevEs => IgvmPlatformType::SEV_ES,
        Platform::SevSnp => IgvmPlatformType::SEV_SNP,
    };
    let compatibility_mask = get_compatibility_mask(&igvm, platform).ok_or(String::from(
        "IGVM file is not compatible with the specified platform.",
    ))?;

    let measure = IgvmMeasure::measure(
        options.verbose,
        options.check_kvm,
        options.native_zero,
        compatibility_mask,
        platform,
        &igvm,
    )?;

    match options.command {
        Commands::Measure {
            ignore_idblock,
            bare,
        } => measure_command(&options, ignore_idblock, bare, &measure)?,
        Commands::Sign {
            output,
            id_key,
            author_key,
        } => {
            if options.platform != Platform::SevSnp {
                return Err("Signing is only supported for SEV-SNP".into());
            }
            sign_command(&output, &id_key, &author_key, &igvm, &measure)?;
        }
    }

    Ok(())
}

fn measure_command(
    options: &CmdOptions,
    ignore_idblock: bool,
    bare: bool,
    measure: &IgvmMeasure,
) -> Result<(), Box<dyn Error>> {
    if !bare {
        println!(
            "\n==============================================================================================================="
        );
        print!("igvmmeasure '{}'\nLaunch Digest: ", options.input);
    }

    measure.digest().iter().for_each(|val| print!("{val:02X}"));
    println!();

    if !bare {
        println!(
            "===============================================================================================================\n"
        );
    }

    if (options.platform == Platform::SevSnp) && !ignore_idblock {
        measure.check_id_block()?;
    }

    Ok(())
}

fn sign_command(
    output: &String,
    id_key: &String,
    author_key: &Option<String>,
    igvm: &IgvmFile,
    measure: &IgvmMeasure,
) -> Result<(), Box<dyn Error>> {
    let id_block = SevIdBlockBuilder::build(igvm, measure)?;
    let id_block_directive = id_block.sign(id_key, author_key)?;

    let mut directives = igvm.directives().to_vec();
    directives.push(id_block_directive);

    let signed_file = IgvmFile::new(
        igvm::IgvmRevision::V1,
        igvm.platforms().to_vec(),
        igvm.initializations().to_vec(),
        directives,
    )
    .inspect_err(|_| {
        eprintln!("Failed to create signed IGVM output file");
    })?;
    let mut binary_file = Vec::new();
    signed_file.serialize(&mut binary_file)?;

    let mut file = File::create(output).inspect_err(|_| {
        eprintln!("Failed to create output file {output}");
    })?;
    file.write_all(binary_file.as_slice()).inspect_err(|_| {
        eprintln!("Failed to write output file {output}");
    })?;

    println!("Successfully created signed file: {output}");
    Ok(())
}
