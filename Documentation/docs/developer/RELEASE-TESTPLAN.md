# Release Testplan

## Testplan for Monthly Development Releases

Here is the list of tests performed for each monthly development release.

### Build all targets

Build all targets in the `configs/` directory.

```
cargo xbuild configs/*.json configs/test/*.json
```

### Development Build + SNP boot test

Build with debug flag enabled and boot VM under SEV-SNP to Linux prompt.

### Development Build + Native boot test

Build with debug flag enabled and boot COCONUT-SVSM in a non-confidential VM.

### Release Build + SNP boot test

Build with release flag enabled and boot VM under SEV-SNP to Linux prompt.

### Release Build + Native boot test

Build with release flag enabled and boot COCONUT-SVSM in a non-confidential VM.

### Fuzzers

Run all the fuzzers included in the project for an extended period of time.
Given that failures in the past usually showed up in the first minute of
fuzzing, for releases the fuzzer runs for a minimum of 10 minutes.


#### Fuzzer: `alloc`

```
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run alloc --strip-dead-code -- -max_total_time=600
```

#### Fuzzer: `bitmap_allocator`

```
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run bitmap_allocator --strip-dead-code -- -max_total_time=600
```

#### Fuzzer: `fs`

```
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run fs --strip-dead-code -- -max_total_time=600
```

#### Fuzzer: `insn`

```
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run insn --strip-dead-code -- -max_total_time=600
```

#### Fuzzer: `page_alloc`

```
RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" cargo +nightly fuzz run page_alloc --strip-dead-code -- -max_total_time=600
```

### `make test`

Run the unit-tests included in the project. This test also runs in CI.

```
make test
```

### `make test-in-svsm`

Run the in-SVSM unit-tests on both AMD SEV-SNP and the native platform.

Commands:

```
make test-in-svsm
TEST_ARGS=--nocc make test-in-svsm
```

### Verus Formal Verifier

Run the formal verification included in the project.

Commands:

```
./scripts/vinstall.sh --use-prebuilt
cd kernel
cargo verify
```

### TPM Test

In the Linux guest OS, check that a TPM2 is available.

```
systemd-analyze has-tpm2
```

### `make clippy CARGO_HACK=1`

Run `clippy` for a wider set of configurations.

```
make clippy CARGO_HACK=1
```

### `cargo audit`

Check the projects dependency tree for known vulnerabilities.

```
cargo audit
```
