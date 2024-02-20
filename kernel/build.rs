// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

fn main() {
    // Stage 2
    println!("cargo:rustc-link-arg-bin=stage2=-nostdlib");
    println!("cargo:rustc-link-arg-bin=stage2=--build-id=none");
    println!("cargo:rustc-link-arg-bin=stage2=-Tkernel/src/stage2.lds");
    println!("cargo:rustc-link-arg-bin=stage2=-no-pie");

    // SVSM 2
    println!("cargo:rustc-link-arg-bin=svsm=-nostdlib");
    println!("cargo:rustc-link-arg-bin=svsm=--build-id=none");
    println!("cargo:rustc-link-arg-bin=svsm=--no-relax");
    println!("cargo:rustc-link-arg-bin=svsm=-Tkernel/src/svsm.lds");
    println!("cargo:rustc-link-arg-bin=svsm=-no-pie");
    if std::env::var("CARGO_FEATURE_MSTPM").is_ok()
        && std::env::var("CARGO_FEATURE_DEFAULT_TEST").is_err()
    {
        println!("cargo:rustc-link-arg-bin=svsm=-Llibmstpm");
        println!("cargo:rustc-link-arg-bin=svsm=-lmstpm");
    }

    // Extra linker args for tests.
    println!("cargo:rerun-if-env-changed=LINK_TEST");
    if std::env::var("LINK_TEST").is_ok() {
        println!("cargo:rustc-cfg=test_in_svsm");
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=--build-id=none");
        println!("cargo:rustc-link-arg=--no-relax");
        println!("cargo:rustc-link-arg=-Tkernel/src/svsm.lds");
        println!("cargo:rustc-link-arg=-no-pie");
    }
}
