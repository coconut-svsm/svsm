// SPDX-License-Identifier: MIT OR Apache-2.0
fn main() {
    println!("cargo:rustc-link-arg-bin=dm=-nostdlib");
    println!("cargo:rustc-link-arg-bin=dm=-no-pie");
    println!("cargo:rustc-link-arg-bin=dm=-Tdm/dm.lds");
}
