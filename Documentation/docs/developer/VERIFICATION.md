VERIFICATION
=======

To run verification, we will need to a few steps to setup the build toolchains.


## Build

### Install verification tools

```
cd svsm
./scripts/vinstall.sh
```

### Build svsm with verification

```
cd svsm/kernel
cargo verify
```

By default, it will verify all crates (except for vstd), if you do not want to
verify other crates, use `cargo verify --features verus_no_dep_verify`.


### Pass verus arguments for verification.

It is helpful to pass extra args for verification debugging.

You can pass extra verus arguments via {crate}_{lib/bin}_VERUS_ARGS to a specific crate
{crate} or VERUS_ARGS to all crates.

`svsm_lib_VERUS_ARGS="--no-verify" cargo verify` compiles the code without verifying
svsm crate.

`svsm_lib_VERUS_ARGS="--verify-module address" cargo verify` verify only address
module in the crate svsm.



### Build without verification

```
cd svsm/kernel
cargo build
```

## Manage specification and proof codes

* Minimize annotations inside executable Rust.
* Define specification and proof code in `*.verus.rs` or in a different crates. Those codes wrapped in verus!{} macro and need verusfmt to format.

```
cd svsm
cargo vfmt
```
