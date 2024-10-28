// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::process::Command;
use std::process::Stdio;

fn main() {
    let output = Command::new("make")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();

    if !output.status.success() {
        panic!();
    }

    // Tell cargo to link libmstpm and where to find it.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rustc-link-search={out_dir}");
    println!("cargo:rustc-link-lib=mstpm");
}
