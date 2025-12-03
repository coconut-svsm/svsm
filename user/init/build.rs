fn main() {
    // Extra cfgs
    println!("cargo::rustc-check-cfg=cfg(test_in_svsm)");

    // Userinit
    println!("cargo:rustc-link-arg-bin=userinit=-Tuser/lib/module.lds");
    println!("cargo:rustc-link-arg-bin=userinit=-no-pie");
    println!("cargo:rustc-link-arg-bin=userinit=-nostdlib");

    // Extra linker args for tests.
    println!("cargo:rerun-if-env-changed=LINK_TEST");
    if std::env::var("LINK_TEST").is_ok() {
        println!("cargo:rustc-cfg=test_in_svsm");
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=-Tuser/lib/module.lds");
        println!("cargo:rustc-link-arg=-no-pie");
    }

    println!("cargo:rerun-if-changed=user/lib/module.lds");
    println!("cargo:rerun-if-changed=build.rs");
}
