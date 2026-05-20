# VERIFICATION

Formal verification is done via [Verus](https://github.com/verus-lang/verus). 
To execute verification, ensure you have set up the necessary tools to run
`cargo verify`.

We provide two options to run verification: GitHub workflow and local build.

## Verification in a Remote Branch via GitHub workflow

When submitting a change related to verification, developers can verify their
modifications by running the [Verification
workflow](../../../.github/workflows/manual-verify.yml). This can be done by
triggering the `Verification` workflow for a specific branch under Actions.

At the moment, only admins can manually trigger this workflow within the
coconut-svsm organization, since verification is still an experimental feature.

Developers can trigger the workflow from their **fork** (e.g.,
https://github.com/USERNAME/svsm/actions/workflows/manual-verify.yml), as long
as both the main branch and the target branch in the fork contain the workflow
file. Running workflow in a fork avoids consuming CI resources from the
organization. After running the workflow on their fork, developers can include
the verification results in their pull request.

## Verification in Local Build

### Setup

Run the following commands to install Verus tools.

```shell
cd svsm
./scripts/vinstall.sh --use-prebuilt
```

The script skips installation if a matching version of Verus is already installed.
To force reinstallation (e.g., some verus-related tools are missing), add the --force flag.
To build both Verus and Z3 from source instead of using prebuilt binaries, omit the --use-prebuilt flag. Building from source is required for CI.

> Can I use latest Verus toolchain?
>> The `vinstall.sh` script and our Cargo dependencies are pinned to a specific
 Verus version, but newer releases may work as well. Verus runs cross-project CI
 to check whether new Verus changes remain compatible with Coconut SVSM.

> Why am I using a different Rust toolchain?
>> Verus requires a specific version of Rust (e.g., 1.88.0) because it depends
  on the compiler’s internal libraries for verification. Thanks to Rust’s strong
  backward compatibility guarantees, Verus can analyze code written against
  older versions. However, some newer Verus features depend on recent rustc
  versions, so we may occasionally upgrade the toolchain to support those
  features, which does not guarantee it is the exact version defined by
  `rust-toolchain.toml`

### Build svsm with verification

```shell
cd svsm/kernel
cargo verify
```

By default, `cargo verify` verifies only the current crate. It is an alias for
`cargo verus focus --features verus` and uses specifications and proofs from
dependency crates without re-verifying them. To verify dependency crates as
well, run `cargo verus verify --features verus`.

### Pass verus arguments for verification

For debugging purposes, it is helpful to pass additional Verus arguments.
You can specify extra arguments using `cargo verify -- $extra_verus_args`

**Examples**

* Compiles a crate without verifying svsm crate using verus compilation:

    ```shell
    cargo verify -- --no-verify
    ```

* Compiles a crate while only verifying address module in svsm crate:

    ```shell
    cargo verify -- --verify-only-module address --verify-function VirtAddr::new
    ```

### Build without verification

```shell
cd svsm/kernel
cargo build
```

All Verus-related annotations, specifications, and proofs are ignored.

## Verification Plan

- [x] Set up verification as an experimental development.
- [ ] Verify SVSM kernel protocol (similar to [VeriSMo](https://github.com/microsoft/verismo))
    - [ ] Allocator
    - [ ] Page table
    - [ ] Protocol
- [ ] Verifying other security-critical components.

## Verification Development

To enable verification, developers need to add annotations in executable Rust
and to write specification and proofs in ghost mode.

### Development Guidelines

* Code Collaboration: Unverified and verified code can co-exist. See [SVSM VeriSMo meeting](https://github.com/coconut-svsm/governance/blob/main/Meetings/Data/verismo-10-23-2024-talk.pdf) for more details.
* Minimize Annotations: Keep simple annotations in executable Rust, by defining
  complicated specifications in spec functions and group proofs.
* Specification and Proof Structure: For each module `x`, define code-related
  specification and proof in `x.verus.rs` .
* Code Formatting: Use `cargo fmt` for excutable Rust. Codes wrapped in verus!{}
  macro could be formatted via verusfmt. Run `./script/vfmt.sh` to format
  `*.verus.rs`
* Reusing spec/proof: Use external specification and proofs from
  [vstd](https://verus-lang.github.io/verus/verusdoc/vstd/) when possible.
* Specifications for dependencies (external crates): If functions, structs, or
  traits from external crates lack specifications from vstd, define their
  specifications in `verification/verify_external/`.
* Performance: Store expensive and reusable proofs in `verification/verify_proof/`
  if not provided by `vstd`. The `svsm/kernel/build.rs` sets `rlimit=1`, while
  `verification/verify_proof/build.rs` sets `rlimit=4`, helping developers
  decide when they need more proof engineering to run verification within
  minutes. For some proofs that are tightly related to the project code, we may
  still put them under svsm/kernel with `#[verus_verify(rlimit=x)]`.

### Annotation in Executable Rust

* `#[verus_verify]`: Indicates the item is Verus-aware.
* `#[verus_verify(external_body)]`: Indicates the item is Verus-aware, but marks the function body as uninterpreted by the verifier.
* `#[verus_verify(external)]`: Instructs Verus to ignore the item. By default, items are treated as #[verus_verify(external)].
* `#[verus_spec($specificaton)]`: Specifies pre/postconditions for executable codes.
  `$specificaton` is in format of:
  ```
  => $ret
  requires precondition($inputs),
  ensures postcondition($inputs, $ret),
  returns ret_spec,
  decreases termination_condition
  ```
* `proof!{...}`: Inserts proofs to help solver to avoid false positives or improve
  performance. You can also add assert(..) inside proof macro to statically
  check assertions.
* More annotations usage can be found in <https://github.com/verus-lang/verus/tree/main/source/rust_verify_test/tests/syntax_attr.rs>


For example,

```rust

use vstd::prelude::*;
#[verus_verify]
trait A: Sized {
  #[verus_spec(ret => requires(m > 0), ensures 0 <= ret < m)]
  fn op(self, m: usize) -> usize;
}

#[verus_verify]
impl A for usize {
  // Failed postcondition.
  fn op(self, m: usize) -> usize {
    self
  }
}

#[verus_verify]
impl A for u64 {
  // Verified.
  fn op(self, m: usize) -> usize {
    (self % (m as u64)) as usize
  }
}
```

### Developing specification and proof (Verification developers)

While Verus allows you to write specifications and proofs in Rust, it's
beneficial to use the `verus!{}` macro for a more concise, mathematical syntax
similar to Dafny, F*, and Coq. To get started, be sure to read the [Verus
Tutorial](https://verus-lang.github.io/verus/guide/overview.html). You can use
[Verus playground](https://play.verus-lang.org/) to play with verus without
install it. To find examples about recursive proof, quantifier, traits,
pointers, type invariant, or other advanced usage, please refer to [Verus
Tests](https://github.com/verus-lang/verus/tree/main/source/rust_verify_test/tests)
and [Verus
Examples](https://github.com/verus-lang/verus/tree/main/examples).
