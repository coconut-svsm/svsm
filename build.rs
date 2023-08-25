// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

fn main() {
    // Stage 2
    println!("cargo:rustc-link-arg-bin=stage2=-nostdlib");
    println!("cargo:rustc-link-arg-bin=stage2=-Wl,--build-id=none");
    println!("cargo:rustc-link-arg-bin=stage2=-Wl,-Tstage2.lds");

    // SVSM 2
    println!("cargo:rustc-link-arg-bin=svsm=-nostdlib");
    println!("cargo:rustc-link-arg-bin=svsm=-Wl,--build-id=none");
    println!("cargo:rustc-link-arg-bin=svsm=-Wl,--no-relax");
    println!("cargo:rustc-link-arg-bin=svsm=-Wl,-Tsvsm.lds");
}
