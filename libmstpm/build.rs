// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::env::current_dir;
use std::process::Command;
use std::process::Stdio;

fn main() {
    // Build libmstpm.
    let status = Command::new("make")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // Tell cargo to link libmstpm and where to find it.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rustc-link-search={out_dir}");
    println!("cargo:rustc-link-lib=mstpm");

    // Tell cargo not to rerun the build-script unless anything in this
    // directory changes.
    let cwd = current_dir().unwrap();
    let cwd = cwd.as_os_str().to_str().unwrap();
    println!("cargo:rerun-if-changed={cwd}");
}
