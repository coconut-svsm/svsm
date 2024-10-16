// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use rustc_version::{Channel, Version};

fn main() {
    let rust_version = rustc_version::version_meta().unwrap();
    // Check if the version is nightly and higher than 1.78.0
    let is_expected_version = rust_version.semver >= Version::new(1, 78, 0);
    if !is_expected_version {
        if rust_version.channel == Channel::Nightly {
            // Print the cargo:rustc-cfg directive to enable the feature
            println!("cargo:rustc-cfg=RUST_BEFORE_1_78");
        } else {
            // Optionally handle the case for non-nightly versions
            panic!("Requires the nightly version or stable version >= 1.78.");
        }
    } else {
        // Extra cfgs
        println!("cargo::rustc-check-cfg=cfg(fuzzing)");
        println!("cargo::rustc-check-cfg=cfg(test_in_svsm)");
        println!("cargo::rustc-check-cfg=cfg(verus_keep_ghost)");
        println!("cargo::rustc-check-cfg=cfg(RUST_BEFORE_1_78)");
    }

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

    println!("cargo:rerun-if-changed=kernel/src/stage2.lds");
    println!("cargo:rerun-if-changed=kernel/src/svsm.lds");
    println!("cargo:rerun-if-changed=build.rs");
    init_verify();
}

fn init_verify() {
    if cfg!(feature = "noverify") {
        println!("cargo:rustc-env=VERUS_ARGS=--no-verify");
    } else {
        let verus_args = [
            "--rlimit=8000",
            "--expand-errors",
            "--multiple-errors=5",
            "--triggers-silent",
            "--no-auto-recommends-check",
            "--trace",
            "-Z unstable-options",
        ];
        println!("cargo:rustc-env=VERUS_ARGS={}", verus_args.join(" "));
    }
}
