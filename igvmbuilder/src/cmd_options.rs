// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub struct CmdOptions {
    /// Stage 2 binary file
    #[arg(short, long)]
    pub stage2: String,

    /// Kernel elf file
    #[arg(short, long)]
    pub kernel: String,

    /// Optional filesystem image
    #[arg(long)]
    pub filesystem: Option<String>,

    /// Optional firmware file, e.g. OVMF.fd
    #[arg(short, long)]
    pub firmware: Option<String>,

    /// Output filename for the generated IGVM file
    #[arg(short, long)]
    pub output: String,

    /// COM port to use for the SVSM console. Valid values are 1-4
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(i32).range(1..=4))]
    pub comport: i32,

    /// Hypervisor to generate IGVM file for
    #[arg(value_enum)]
    pub hypervisor: Hypervisor,

    /// Print verbose output
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Sort the IGVM Page directives by GPA from lowest to highest
    #[arg(long, default_value_t = false)]
    pub sort: bool,
}

impl CmdOptions {
    pub fn get_port_address(&self) -> u16 {
        match self.comport {
            1 => 0x3f8,
            2 => 0x2f8,
            3 => 0x3e8,
            4 => 0x2e8,
            _ => 0,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Hypervisor {
    /// Build an IGVM file compatible with QEMU
    QEMU,

    /// Build an IGVM file compatible with Hyper-V
    HyperV,
}
