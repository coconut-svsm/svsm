// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>

fn main() {
    init_verify();
}

fn init_verify() {
    if cfg!(feature = "noverify") {
        println!("cargo:rustc-env=VERUS_ARGS=--no-verify");
    } else {
        // Set rlimit higher here for expensive but reusable proofs.
        let verus_args = [
            "--rlimit=4",
            "--expand-errors",
            "--multiple-errors=5",
            "--no-auto-recommends-check",
            "--trace",
            "-Z unstable-options",
        ];
        println!("cargo:rustc-env=VERUS_ARGS={}", verus_args.join(" "));
    }
}
