// SPDX-License-Identifier: MIT OR Apache-2.0
//

fn main() {
    // Extra cfgs
    println!("cargo::rustc-check-cfg=cfg(test_in_svsm)");

    // uapi_tester
    println!("cargo::rustc-link-arg-bin=uapi_tester=-Tuser/lib/module.lds");
    println!("cargo::rustc-link-arg-bin=uapi_tester=-no-pie");
    println!("cargo::rustc-link-arg-bin=uapi_tester=-nostdlib");

    // Extra linker args for tests.
    println!("cargo::rerun-if-env-changed=LINK_TEST");
    if std::env::var("LINK_TEST").is_ok() {
        println!("cargo::rustc-cfg=test_in_svsm");
        println!("cargo::rustc-link-arg=-nostdlib");
        println!("cargo::rustc-link-arg=-Tuser/lib/module.lds");
        println!("cargo::rustc-link-arg=-no-pie");
    }

    println!("cargo::rerun-if-changed=user/lib/module.lds");
    println!("cargo::rerun-if-changed=build.rs");
}
