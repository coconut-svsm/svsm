// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]

pub mod acpi;
pub mod address;
pub mod console;
pub mod cpu;
pub mod debug;
pub mod elf;
pub mod error;
pub mod fs;
pub mod fw_cfg;
pub mod fw_meta;
pub mod io;
pub mod kernel_launch;
pub mod locking;
pub mod mm;
pub mod protocols;
pub mod requests;
pub mod serial;
pub mod sev;
pub mod string;
pub mod svsm_console;
pub mod types;
pub mod utils;

#[test]
fn test_nop() {}
