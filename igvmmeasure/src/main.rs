// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;

use clap::Parser;
use cmd_options::CmdOptions;
use igvm_measure::IgvmMeasure;

mod cmd_options;
mod igvm_measure;
mod page_info;

fn main() -> Result<(), Box<dyn Error>> {
    let options = CmdOptions::parse();
    let mut igvm = IgvmMeasure::new(&options);
    let digest = igvm.measure()?;

    if !options.bare {
        println!(
            "\n==============================================================================================================="
        );
        print!("igvmmeasure '{}'\nLaunch Digest: ", options.igvm_file);
    }

    digest.iter().for_each(|val| print!("{:02X}", val));
    println!();

    if !options.bare {
        println!(
            "===============================================================================================================\n"
        );
    }

    Ok(())
}
