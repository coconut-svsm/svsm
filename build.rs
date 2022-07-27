// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

fn main() {
    // Stage 2
    println!("cargo:rustc-link-arg-bin=stage2=-nostdlib");
    println!("cargo:rustc-link-arg-bin=stage2=-Wl,--build-id=none");
    println!("cargo:rustc-link-arg-bin=stage2=-Wl,-Tstage2.lds");

    // SVSM 2
    println!("cargo:rustc-link-arg-bin=svsm=-nostdlib");
    println!("cargo:rustc-link-arg-bin=svsm=-Wl,--build-id=none");
    println!("cargo:rustc-link-arg-bin=svsm=-Wl,-Tsvsm.lds");
}
