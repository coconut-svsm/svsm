// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

fn main() {
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-Tboot/bldr/src/bldr.lds");
    println!("cargo:rustc-link-arg=-no-pie");

    println!("cargo:rerun-if-changed=boot/bldr/src/bldr.lds");
    println!("cargo:rerun-if-changed=build.rs");
}
