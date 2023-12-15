FUZZING
=======

The COCONUT SVSM includes several fuzzing harnesses to find bugs in
security-critical interfaces. These do not currently provide coverage
of all interesting interfaces, so contributions are welcome.

At the moment, fuzzing is done through
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). You may find a
complete tutorial for this tool on the
[rust-fuzz website](https://rust-fuzz.github.io/book/cargo-fuzz.html).

Requirements
------------

* Rust nightly toolchain (`rustup toolchain install nightly`)
* cargo
* cargo-fuzz (`cargo install cargo-fuzz`)
* LLVM C toolchain (`clang` and `lld`)

Running a harness
-----------------

To get a list of harnesses, simply run the `list` subcommand:

```bash
cargo fuzz list
```

To build a harness you may use the `build` subcommand. You may also use
the `run` subcommand, as detailed a few lines below.

Since `cargo-fuzz` relies on clang's [libFuzzer](https://llvm.org/docs/LibFuzzer.html),
and there are extra compilation flags that need to be set, one must
specify the clang linker, as well as use the nightly Rust toolchain.
Additionally, you might need to strip dead code to avoid build errors.
The following will build all harnesses:

```bash
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz build --strip-dead-code
```

As mentioned before, you may run a specific harness, building it if
needed, by using the `run` subcommand and specifying its name. The
following will run the `fw_meta` fuzzer:


```bash
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run fw_meta --strip-dead-code
```

The generated test cases, as well as any found crashes, will be placed
under the `fuzz/` subdirectory.

Developing a harness
--------------------

You may add a new harness via the `add` subcommand:

```bash
cargo fuzz add my_harness
```

After that, you may run your harness normally:

```bash
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run my_harness --strip-dead-code
```

The main file with a basic template will be placed under
`fuzz/fuzz_targets/my_harness.rs`. The main code of your harness should
be placed inside the `fuzz_target!()` macro. For more information refer
to the [`libfuzzer-sys`](https://docs.rs/libfuzzer-sys/0.4.7/libfuzzer_sys/macro.fuzz_target.html)
documentation.

When a fuzzer is built, the `fuzzing` cfg item is defined. This might be
useful to conditionally compile code, although it is advised that you
do not rely on this feature too often.

For example, the following code disables the SVSM allocator during
fuzzing and tests:

```rust
#[cfg_attr(not(any(test, doctest, fuzzing)), global_allocator)]
pub static mut ALLOCATOR: SvsmAllocator = SvsmAllocator::new();
```

