// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::env::current_dir;
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
    let cwd = current_dir().unwrap();
    let cwd = cwd.as_os_str().to_str().unwrap();
    println!("cargo:rustc-link-search={cwd}");
    println!("cargo:rustc-link-lib=mstpm");
}
