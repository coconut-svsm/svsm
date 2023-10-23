// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]
#![cfg_attr(all(test, test_in_svsm), no_main)]
#![cfg_attr(all(test, test_in_svsm), feature(custom_test_frameworks))]
#![cfg_attr(all(test, test_in_svsm), test_runner(crate::testing::svsm_test_runner))]
#![cfg_attr(all(test, test_in_svsm), reexport_test_harness_main = "test_main")]

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
pub mod svsm_paging;
pub mod task;
pub mod types;
pub mod utils;

#[test]
fn test_nop() {}

// When running tests inside the SVSM:
// Build the kernel entrypoint.
#[cfg(all(test, test_in_svsm))]
#[path = "svsm.rs"]
pub mod svsm_bin;
// The kernel expects to access this crate as svsm, so reexport.
#[cfg(all(test, test_in_svsm))]
extern crate self as svsm;
// Include a module containing the test runner.
#[cfg(all(test, test_in_svsm))]
pub mod testing;
