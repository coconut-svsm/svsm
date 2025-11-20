// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>
#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, File};
use std::io::Write;

use clap::Parser;
use cmd_options::{CmdOptions, Commands, Platform};
use igvm::IgvmFile;
use igvm_defs::IgvmPlatformType;
use igvm_measure::IgvmMeasure;
use utils::get_compatibility_mask;
use zerocopy::IntoBytes;

use crate::id_block::SevIdBlockBuilder;

mod cmd_options;
mod id_block;
mod igvm_measure;
mod page_info;
mod utils;

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

    measure
        .digest()
        .iter()
        .for_each(|val| print!("{:02X}", val));
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
        eprintln!("Failed to create output file {}", output);
    })?;
    file.write_all(binary_file.as_slice()).inspect_err(|_| {
        eprintln!("Failed to write output file {}", output);
    })?;

    println!("Successfully created signed file: {}", output);
    Ok(())
}
