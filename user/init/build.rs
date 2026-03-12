// SPDX-License-Identifier: MIT OR Apache-2.0
//

fn main() {
    println!("cargo:rustc-link-arg=-Tuser/lib/module.lds");
    println!("cargo:rustc-link-arg=-no-pie");
}
