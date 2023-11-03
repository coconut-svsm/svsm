// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]
#![deny(missing_copy_implementations)]
#![deny(missing_debug_implementations)]
#![cfg_attr(all(test, any(test_in_svsm, test_in_stage2)), no_main)]
#![cfg_attr(
    all(test, any(test_in_svsm, test_in_stage2)),
    feature(custom_test_frameworks)
)]
#![cfg_attr(
    all(test, any(test_in_svsm, test_in_stage2)),
    test_runner(crate::testing::svsm_test_runner)
)]
#![cfg_attr(
    all(test, any(test_in_svsm, test_in_stage2)),
    reexport_test_harness_main = "test_main"
)]

pub mod acpi;
pub mod address;
pub mod console;
pub mod cpu;
pub mod crypto;
pub mod debug;
pub mod elf;
pub mod error;
pub mod fs;
pub mod fw_cfg;
pub mod fw_meta;
pub mod greq;
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
#[cfg(all(test, any(test_in_svsm, test_in_stage2)))]
extern crate self as svsm;
// Include a module containing the test runner.
#[cfg(all(test, any(test_in_svsm, test_in_stage2)))]
pub mod testing;

// When running tests inside the SVSM:
// Build the kernel entrypoint.
#[cfg(all(test, test_in_stage2))]
#[path = "stage2.rs"]
pub mod stage2_bin;
