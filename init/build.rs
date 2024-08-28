// SPDX-License-Identifier: MIT OR Apache-2.0
fn main() {
    println!("cargo:rustc-link-arg-bin=init=-nostdlib");
    println!("cargo:rustc-link-arg-bin=init=-no-pie");
    println!("cargo:rustc-link-arg-bin=init=-Tinit/init.lds");
}
