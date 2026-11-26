// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn git_reset(submodule_dir: &Path) {
    // Reset the submodule to the commit recorded in the superproject,
    // initializing it if necessary.
    let status = Command::new("git")
        .args(["submodule", "update", "--init"])
        .arg(submodule_dir.file_name().unwrap())
        .current_dir(submodule_dir.parent().unwrap())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap_or_else(|e| panic!("failed to run git submodule update: {e}"));
    assert!(
        status.success(),
        "failed to reset the submodule at {} to the commit recorded in the superproject",
        submodule_dir.display()
    );
}

fn apply_patch(patch: &Path, submodule_dir: &Path) {
    // use an explicit committer identity in case git is not fully set up
    // (for example CI)
    let status = Command::new("git")
        .arg("-c")
        .arg(format!("user.name=libtcgtpm-build"))
        .arg("-c")
        .arg(format!("user.email=libtcgtpm@localhost"))
        .arg("am")
        .arg("-3")
        .arg("--committer-date-is-author-date")
        .arg(patch)
        .current_dir(submodule_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap_or_else(|e| panic!("failed to run git am: {e}"));

    if !status.success() {
        panic!(
            "failed to apply {} to {}",
            patch.display(),
            submodule_dir.display()
        );
    }
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let tpm_dir = manifest_dir.join("deps/tpm-20-ref");
    let tpm_patch_dir = manifest_dir.join("patches/tpm-20-ref");
    git_reset(&tpm_dir);
    apply_patch(
        &tpm_patch_dir.join("0001-Address-improper-object-slot-reuse.patch"),
        &tpm_dir,
    );
    apply_patch(
        &tpm_patch_dir.join("0002-Address-RSA-OAEP-timing-side-channel-vulnerability.patch"),
        &tpm_dir,
    );

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Build libtcgtpm.
    let mut cmd = Command::new("make");
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
        .clang_arg("-isystemdeps/libcrt/include/")
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

    println!("cargo:rustc-link-search={out_dir}/openssl-build");
    println!("cargo:rustc-link-lib=crypto");

    if target_os == "none" {
        println!("cargo:rustc-link-search={out_dir}/libcrt-build");
        println!("cargo:rustc-link-lib=crt");
    }

    // Tell cargo not to rerun the build-script unless anything in this
    // directory changes.
    println!("cargo:rerun-if-changed={}", manifest_dir.display());
}
