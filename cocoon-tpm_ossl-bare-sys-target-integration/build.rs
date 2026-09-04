// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

use std::env;
use std::path::PathBuf;

fn main() {
    // See ossl-bare-sys' build.rs for a list and meaning of metadata variables recognized.
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // libcrt is built by the libcrt crate. Read its include path for CPPFLAGS.
    let libcrt_include_dir = env::var("DEP_CRT_INCLUDE_DIR").expect("DEP_CRT_INCLUDE_DIR not set");

    // Use the custom SVSM OpenSSL target configuration.
    let config_file = src_dir.join("third-party").join("openssl_svsm.conf");
    println!("cargo::rerun-if-changed={}", config_file.to_str().unwrap());
    println!(
        "cargo::metadata=CONFIGURE_CONFIG_FILE={}",
        config_file.to_str().unwrap()
    );
    println!("cargo::metadata=CONFIGURE_TARGET=SVSM");

    // SVSM is a no-threads, freestanding embedded environment.
    // Only options specific to the embedded target belong here — algorithm
    // selection lives in cocoon-tpm/ossl-bare-sys/build.rs.
    let configure_args = [
        // Do not use assembler code.
        "no-asm",
        // Do not use atexit() in libcrypto builds.
        "no-atexit",
        // Don't automatically load all libcrypto/libssl error strings.
        "no-autoerrinit",
        // Don't compile in any error strings.
        "no-err",
        // Don't compile in filename and line number information.
        "no-filenames",
        // Don't build with support for Position Independent Code.
        "no-pic",
        // Don't use POSIX IO capabilities.
        "no-posix-io",
        // Exclude SSE2 code paths from assembly modules.
        "no-sse2",
        // Don't use anything from stdio.h.
        "no-stdio",
        // Don't build with support for multi-threaded applications.
        "no-threads",
        // Don't build with support for thread pool functionality.
        "no-thread-pool",
        // Use only getrandom() for CSPRNG seeding.
        "--with-rand-seed=getrandom",
    ];
    let mut configure_args = configure_args.join(" ");

    // Cross-compile support: when the host is not x86_64, use the cross
    // toolchain for OpenSSL Configure, the shim library, and make.
    let host = env::var("HOST").unwrap();
    if !host.starts_with("x86_64") {
        configure_args.push_str(" --cross-compile-prefix=x86_64-linux-gnu-");
        println!("cargo::metadata=CC=x86_64-linux-gnu-gcc");
    }

    println!("cargo::metadata=CONFIGURE_ARGS={configure_args}");

    // The SVSM conf sets CFLAGS and lib_cppflags for the OpenSSL build itself,
    // but the shim library and bindgen also need the libcrt include path.
    let cppflags = format!("-I{libcrt_include_dir}");
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
    // When cross-compiling, also tell clang the target triple so it uses
    // the correct type sizes and ABI.
    let mut bindgen_cflags = cppflags.clone();
    if !host.starts_with("x86_64") {
        bindgen_cflags.push_str(" --target=x86_64-unknown-none");
    }
    println!("cargo::metadata=BINDGEN_CFLAGS={bindgen_cflags}");
}
