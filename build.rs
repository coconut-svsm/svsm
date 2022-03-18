fn main() {
	// Stage 2
	println!("cargo:rustc-link-arg-bin=stage2=-nostdlib");
	println!("cargo:rustc-link-arg-bin=stage2=-Wl,--build-id=none");
	println!("cargo:rustc-link-arg-bin=stage2=-Wl,-Tstage2.lds");
}
