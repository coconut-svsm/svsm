// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir);

    let libcrt_src_dir = src_dir.join("c");
    println!(
        "cargo::rerun-if-changed={}",
        libcrt_src_dir.to_str().unwrap()
    );

    let target = env::var("TARGET").unwrap();
    let libcrt_build_dir = out_path.join("libcrt");

    // Only compile and link the C runtime for bare-metal targets.
    // For host builds (tests), the system libc provides these symbols.
    // Linking the bare-metal C objects on the host causes hidden-visibility
    // conflicts (-fPIE triggers #pragma GCC visibility push(hidden) in
    // libcrt.h, making all symbol references unsatisfiable by shared libs).
    //
    // TODO: The target-integration crate should be made target-conditional so
    // the entire SVSM-specific build pipeline (libcrt, SVSM OpenSSL config,
    // custom CFLAGS/CPPFLAGS) is skipped for host builds. Currently, host
    // test builds still pull in the integration crate and configure OpenSSL
    // with SVSM flags — only the C library link is skipped here as a
    // workaround.
    if target.ends_with("-none") {
        std::fs::create_dir_all(&libcrt_build_dir).unwrap();

        let status = Command::new("make")
            .arg("-C")
            .arg(&libcrt_src_dir)
            .arg(format!("OUT_DIR={}", libcrt_build_dir.to_str().unwrap()))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap();
        assert!(status.success());

        println!(
            "cargo::rustc-link-search={}",
            libcrt_build_dir.to_str().unwrap()
        );
        println!("cargo::rustc-link-lib=static=crt");
    }

    let libcrt_include = libcrt_src_dir.join("include");
    println!(
        "cargo::metadata=INCLUDE_DIR={}",
        libcrt_include.to_str().unwrap()
    );
    println!(
        "cargo::metadata=LIB_DIR={}",
        libcrt_build_dir.to_str().unwrap()
    );
}
