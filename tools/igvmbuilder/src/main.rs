// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use gpa_map::GpaMap;
use igvm_builder::IgvmBuilder;
use std::error::Error;

mod boot_params;
mod cmd_options;
mod context;
mod cpuid;
mod firmware;
mod gpa_map;
mod igvm_builder;
mod igvm_firmware;
mod ovmf_firmware;
mod paging;
mod platform;
mod sipi;
mod stage2_stack;

fn main() -> Result<(), Box<dyn Error>> {
    let builder = IgvmBuilder::new()?;
    builder.build()?;
    Ok(())
}
