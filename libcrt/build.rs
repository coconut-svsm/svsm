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

    // Only compile and link the C runtime for bare-metal targets.
    // For host builds (tests), the system libc provides these symbols.
    if target.ends_with("-none") {
        let libcrt_build_dir = out_path.join("libcrt");
        std::fs::create_dir_all(&libcrt_build_dir).unwrap();

        // Cross-compile support: when the host is not x86_64, use a cross toolchain.
        let host = std::env::var("HOST").unwrap();
        let cc = if host.starts_with("x86_64") {
            "gcc".to_string()
        } else {
            "x86_64-linux-gnu-gcc".to_string()
        };

        let status = Command::new("make")
            .arg("-C")
            .arg(&libcrt_src_dir)
            .arg(format!("OUT_DIR={}", libcrt_build_dir.to_str().unwrap()))
            .arg(format!("CC={cc}"))
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
}
