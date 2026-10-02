// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::env::current_dir;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Read OpenSSL paths from cocoon-tpm-ossl-bare-sys (via cargo metadata).
    let ossl_include_dir =
        std::env::var("DEP_OSSL_OSSL_INCLUDE_DIR").expect("DEP_OSSL_OSSL_INCLUDE_DIR not set");
    let ossl_src_include_dir = std::env::var("DEP_OSSL_OSSL_SRC_INCLUDE_DIR")
        .expect("DEP_OSSL_OSSL_SRC_INCLUDE_DIR not set");
    let ossl_lib_dir =
        std::env::var("DEP_OSSL_OSSL_LIB_DIR").expect("DEP_OSSL_OSSL_LIB_DIR not set");

    // Read libcrt include path from the libcrt crate (via cargo metadata).
    let libcrt_include_dir =
        std::env::var("DEP_CRT_INCLUDE_DIR").expect("DEP_CRT_INCLUDE_DIR not set");

    // Build libtcgtpm. OpenSSL (libcrypto) and libcrt come from ossl-bare-sys and libcrt crate
    // respectively.
    let mut cmd = Command::new("make");
    cmd.arg(format!("OPENSSL_INCLUDE_DIR={ossl_include_dir}"));
    cmd.arg(format!("OPENSSL_SRC_INCLUDE_DIR={ossl_src_include_dir}"));
    cmd.arg(format!("OPENSSL_LIB_DIR={ossl_lib_dir}"));
    cmd.arg(format!("LIBCRT_INCLUDE_DIR={libcrt_include_dir}"));
    if target_os != "none" {
        cmd.arg("USE_LIBCRT=0");
    }
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());

    let bindings = bindgen::Builder::default()
        .header("deps/tpm-20-ref/TPMCmd/Platform/include/Platform.h".to_string())
        .allowlist_function("_plat__RunCommand")
        .allowlist_function("_plat__LocalitySet")
        .allowlist_function("_plat__SetNvAvail")
        .allowlist_function("_plat__Signal_PowerOn")
        .allowlist_function("_plat__Signal_Reset")
        .allowlist_function("_plat__NVDisable")
        .allowlist_function("_plat__NVEnable")
        .allowlist_function("_plat__NVNeedsManufacture")
        .allowlist_function("TPM_Manufacture")
        .use_core()
        .clang_arg("-Wno-incompatible-library-redeclaration")
        .clang_arg("-nostdinc")
        .clang_arg(format!("-isystem{libcrt_include_dir}"))
        .clang_arg("-fno-pie") // libcrt.h hides symbols if pie is enabled
        .clang_arg("-Ideps/tpm-20-ref/TPMCmd/tpm/include")
        .clang_arg("-Ideps/TpmConfiguration")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .unwrap_or_else(|_| panic!("Unable to generate bindings for deps/libtcgtpm.h"));

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap_or_else(|_| panic!("Unable to write bindings.rs"));

    // 'static=...' is needed because core lib + platform lib have
    // circular dependencies.
    println!("cargo:rustc-link-search={out_dir}/tcgtpm-build/tpm/src");
    println!("cargo:rustc-link-lib=static=Tpm_CoreLib");
    println!("cargo:rustc-link-search={out_dir}/tcgtpm-build/Platform");
    println!("cargo:rustc-link-lib=static=Tpm_PlatformLib");

    println!("cargo:rustc-link-search={out_dir}/tcgtpm-build/tpm/cryptolibs/TpmBigNum");
    println!("cargo:rustc-link-lib=Tpm_CryptoLib_TpmBigNum");

    println!("cargo:rustc-link-search={out_dir}/tcgtpm-build/cryptolib_Ossl");
    println!("cargo:rustc-link-lib=Tpm_CryptoLib_Math_Ossl");

    // libcrypto and libcrt are provided by cocoon-tpm-ossl-bare-sys and libcrt crate respectively, at link time.

    // Tell cargo not to rerun the build-script unless anything in this
    // directory changes.
    let cwd = current_dir().unwrap();
    let cwd = cwd.as_os_str().to_str().unwrap();
    println!("cargo:rerun-if-changed={cwd}");
}
