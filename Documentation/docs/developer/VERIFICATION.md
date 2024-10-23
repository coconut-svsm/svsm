# VERIFICATION

Formal verification is done via [Verus](https://github.com/verus-lang/verus).
To run verification, you need to setup the verification tools in order to run
`cargo verify`.

## Setup

Run the following commands to install verus and cargo-verify.

```
cd svsm
./scripts/vinstall.sh
```

## Build

### Build svsm with verification

```
cd svsm/kernel
cargo verify
```

By default, it only verifies the current crate.


### Pass verus arguments for verification.

For debugging purposes, it may be helpful to pass additional Verus arguments.
You can specify extra arguments using environmental variable
{crate}_{lib/bin}_VERUS_ARGS to a specific crate
{crate} or VERUS_ARGS to all crates.

**Examples**

* Compiles a crate without verifying svsm crate:

    ```
    svsm_lib_VERUS_ARGS="--no-verify" cargo verify
    ```

* Compiles a crate while only verifying address module in svsm crate:

    ```
    svsm_lib_VERUS_ARGS="--verify-module address" cargo verify
    ```



### Build without verification

```
cd svsm/kernel
cargo build
```

## Developing specification and proof

While Verus allows you to write specifications and proofs in Rust, it's
beneficial to use the verus!{} macro for a more concise, mathematical syntax
similar to Dafny, F*, and Coq. To get started, be sure to read the [Verus
Tutorial](https://verus-lang.github.io/verus/guide/overview.html)


### Development Guidelines

* Minimize annotations inside executable Rust.
* For a module `x`, define code-related specification and proof in `x.verus.rs` .
* Codes wrapped in verus!{} macro could be formatted via verusfmt.
  ./script/vfmt.sh triggers verusfmt for `*.verus.rs`
* Use external specification and proofs from
  [vstd](https://verus-lang.github.io/verus/verusdoc/vstd/) when possible.
* When verifying with functions/structs/traits from external crates, define
  specifications in `verify_external/` if `vstd` does not provide.
* Expensive and reusable proofs are stored in `verify_proof/` if `vstd` does not
  provide.

```
cd svsm
cargo vfmt
```
