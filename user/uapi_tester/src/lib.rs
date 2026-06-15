// SPDX-License-Identifier: MIT OR Apache-2.0
//

//! This is a user-space module used for testing inside SVSM. It is not meant
//! to be built outside of a test environment and will fail to compile in that case.
//! It contains simple tests to verify the correctness of syscall handling

#![no_std]
#![cfg_attr(
    all(test, test_in_svsm),
    no_main,
    feature(custom_test_frameworks),
    test_runner(userlib::testing::svsm_usermodule_test_runner),
    reexport_test_harness_main = "usermodule_tests_in_svsm"
)]

#[test]
fn test_nop() {}

// When running tests inside the SVSM:
// Build the crate entrypoint.
#[cfg(all(test, test_in_svsm))]
#[path = "main.rs"]
pub mod uapi_tester;
