// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

fn main() {
    println!("cargo:rustc-link-arg-bin=stage1=-nostdlib");
    println!("cargo:rustc-link-arg-bin=stage1=--build-id=none");
    println!("cargo:rustc-link-arg-bin=stage1=-Tstage1/stage1.lds");
    println!("cargo:rustc-link-arg-bin=stage1=-no-pie");
    println!("cargo:rustc-link-arg-bin=stage1=-no-gc-sections");

    println!("cargo:rerun-if-changed=stage1.lds");
}
