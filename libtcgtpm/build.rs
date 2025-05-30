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
    // Build libtcgtpm.
    let status = Command::new("make")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());

    let bindings = bindgen::Builder::default()
        .header("deps/libtcgtpm.h".to_string())
        .allowlist_file("deps/libtcgtpm.h")
        .use_core()
        .clang_arg("-Wno-incompatible-library-redeclaration")
        .clang_arg("-isystemdeps/libcrt/include/")
        .clang_arg("-fno-pie") // libcrt.h hides symbols if pie is enabled
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .unwrap_or_else(|_| panic!("Unable to generate bindings for deps/libtcgtpm.h"));

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap_or_else(|_| panic!("Unable to write bindings.rs"));

    // Tell cargo to link libtcgtpm and where to find it.
    println!("cargo:rustc-link-search={out_dir}");
    println!("cargo:rustc-link-lib=tcgtpm");

    // Tell cargo not to rerun the build-script unless anything in this
    // directory changes.
    let cwd = current_dir().unwrap();
    let cwd = cwd.as_os_str().to_str().unwrap();
    println!("cargo:rerun-if-changed={cwd}");
}
