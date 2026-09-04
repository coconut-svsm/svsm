// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    // See ossl-bare-sys' build.rs for a list and meaning of metadata variables recognized.
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir);

    // Build the minimal libc (libcrt).
    let libcrt_src_dir = src_dir.join("third-party").join("libcrt");
    println!("cargo::rerun-if-changed={}", libcrt_src_dir.to_str().unwrap());

    let libcrt_build_dir = out_path.join("libcrt");
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

    // Tell ossl-bare-sys where to find the libcrt for linking.
    println!(
        "cargo::metadata=LINK_SEARCH={}",
        libcrt_build_dir.to_str().unwrap()
    );
    println!("cargo::metadata=LINK_LIB=crt");

    // Use the custom SVSM OpenSSL target configuration.
    let config_file = src_dir.join("third-party").join("openssl_svsm.conf");
    println!(
        "cargo::rerun-if-changed={}",
        config_file.to_str().unwrap()
    );
    println!(
        "cargo::metadata=CONFIGURE_CONFIG_FILE={}",
        config_file.to_str().unwrap()
    );
    println!("cargo::metadata=CONFIGURE_TARGET=SVSM");

    // SVSM is a no-threads, freestanding embedded environment.
    // Disable everything not needed to minimize libc surface.
    let configure_args = [
        // No threading support.
        "no-threads",
        "no-thread-pool",
        // No error strings (error codes still work).
        "no-err",
        // Crypto algorithms not needed for TPM.
        "no-bf",
        "no-blake2",
        "no-chacha",
        "no-cmac",
        "no-cmp",
        "no-cms",
        "no-ct",
        // NOT no-deprecated: we need the legacy HMAC API (HMAC_CTX_new etc.).
        "no-des",
        "no-dh",
        "no-dsa",
        "no-ec2m",
        "no-ecx",
        "no-egd",
        "no-ml-dsa",
        "no-ml-kem",
        "no-ocb",
        "no-ocsp",
        "no-pic",
        "no-rfc3779",
        "no-rmd160",
        "no-scrypt",
        // Only use getrandom for entropy seeding.
        "--with-rand-seed=getrandom",
    ];
    println!(
        "cargo::metadata=CONFIGURE_ARGS={}",
        configure_args.join(" ")
    );

    // The SVSM conf sets CFLAGS and lib_cppflags for the OpenSSL build itself,
    // but the shim library and bindgen also need the libcrt include path.
    let libcrt_include = libcrt_src_dir.join("include");
    let cppflags = format!("-I{}", libcrt_include.to_str().unwrap());
    println!("cargo::metadata=CPPFLAGS={cppflags}");

    // The shim library must use the same code generation flags as OpenSSL for
    // the SVSM target. Only code-gen flags — not -nostdinc/-nostdlib/-static
    // which would break header resolution for the cc crate.
    let cflags = [
        "-fPIE",
        "-m64",
        "-fno-stack-protector",
        "-mno-red-zone",
        "-ffunction-sections",
        "-fdata-sections",
    ];
    println!("cargo::metadata=CFLAGS={}", cflags.join(" "));

    // Bindgen needs the libcrt headers to parse OpenSSL headers.
    println!("cargo::metadata=BINDGEN_CFLAGS={cppflags}");
}
