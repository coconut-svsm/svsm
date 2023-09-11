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
}
