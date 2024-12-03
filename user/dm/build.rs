fn main() {
    println!("cargo:rustc-link-arg=-Tuser/lib/module.lds");
    println!("cargo:rustc-link-arg=-no-pie");
}
