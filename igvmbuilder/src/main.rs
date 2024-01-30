// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use gpa_map::GpaMap;
use igvm_builder::IgvmBuilder;
use std::error::Error;

mod cmd_options;
mod cpuid;
mod firmware;
mod gpa_map;
mod igvm_builder;
mod igvm_firmware;
mod igvm_params;
mod ovmf_firmware;
mod stage2_stack;
mod vmsa;

fn main() -> Result<(), Box<dyn Error>> {
    let builder = IgvmBuilder::new()?;
    builder.build()?;
    Ok(())
}
