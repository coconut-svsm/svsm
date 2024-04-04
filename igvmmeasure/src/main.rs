// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs;

use clap::Parser;
use cmd_options::{CmdOptions, Commands};
use igvm::IgvmFile;
use igvm_defs::IgvmPlatformType;
use igvm_measure::IgvmMeasure;
use utils::get_compatibility_mask;
use zerocopy::AsBytes;

mod cmd_options;
mod igvm_measure;
mod page_info;
mod utils;

fn main() -> Result<(), Box<dyn Error>> {
    let options = CmdOptions::parse();

    let igvm_buffer = fs::read(&options.input).map_err(|e| {
        eprintln!("Failed to open firmware file {}", options.input);
        e
    })?;
    let igvm = IgvmFile::new_from_binary(igvm_buffer.as_bytes(), None)?;
    let compatibility_mask = get_compatibility_mask(&igvm, IgvmPlatformType::SEV_SNP).ok_or(
        String::from("IGVM file is not compatible with the specified platform."),
    )?;

    let measure = IgvmMeasure::measure(
        options.verbose,
        options.check_kvm,
        options.native_zero,
        compatibility_mask,
        &igvm,
    )?;

    match options.command {
        Commands::Measure {
            ignore_idblock,
            bare,
        } => measure_command(&options, ignore_idblock, bare, &measure)?,
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

    if !ignore_idblock {
        measure.check_id_block()?;
    }

    Ok(())
}
