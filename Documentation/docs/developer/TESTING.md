# TESTING

The COCONUT SVSM includes unit and integration tests for multiple subsystems.
This document describes how to run these tests.

## Userspace tests

Tests can be run as regular userspace binaries via `cargo test`. These tests
have no additional requirements, as they use your host's target triple with the
same toolchain version as the rest of the codebase.

```shell
make test
```

## In-SVSM tests

Some tests depend on functionality that is only available when the SVSM is
running in its native environment (e.g. as a bare-metal OS). This section
explains how to run these tests inside a hypervisor.

### Requirements

As of writing, the IGVM file used to run in-SVSM tests can only be built using
the Rust nightly toolchain, e.g.

```shell
rustup toolchain install nightly
rustup +nightly target add x86_64-unknown-none
```

Just like booting a regular build of the SVSM, this requires a QEMU version
built as specified in the [INSTALL.md](../installation/INSTALL.md) document.
The path to the QEMU binary must be passed to the relevant script (see below).

### Running

```shell
QEMU=/path/to/qemu ./scripts/test-in-svsm.sh
# or
QEMU=/path/to/qemu make test-in-svsm
```

The Makefile target will (re)build the relevant code for you before launching
qemu, whereas the script will simply pick up `bin/coconut-test-qemu.igvm` as
the IGVM file to launch.

Tests may even be run in environments without confidential computing support
(native mode) by passing `--nocc` which uses TCG (Emulation) instead of KVM, for
example:

```shell
QEMU=/path/to/qemu ./scripts/test-in-svsm.sh --nocc
# or
QEMU=/path/to/qemu make test-in-svsm TEST_ARGS='--nocc'
```

`test-in-svsm.sh` is a wrapper around `launch_guest.sh`, and parameters
may be forwarded to it, for example:

```shell
QEMU=/path/to/qemu ./scripts/test-in-svsm.sh --nocc -- --no-netdev
# or
QEMU=/path/to/qemu make test-in-svsm TEST_ARGS='--nocc -- --no-netdev'
```

A list of parameters for `launch_guest.sh` is listed in the
[INSTALL.md](../installation/INSTALL.md) document.

## Attestation tests

Attestation can be tested in the same infrastructure by running the
attest-enabled test image together with `kbs-test` and `aproxy`.

### Requirements

In addition to the requirements for in-SVSM tests, attestation tests require:

- The `kbs-test` server from [coconut-svsm/kbs-test](https://github.com/coconut-svsm/kbs-test)
- The `aproxy` binary (built automatically as part of the SVSM build)

### Running

Clone and build `kbs-test`:

```shell
git clone https://github.com/coconut-svsm/kbs-test.git ../kbs-test
```

Run attestation tests:

```shell
KBS_TEST_DIR=../kbs-test QEMU=/path/to/qemu \
make FEATURES_TEST=vtpm,virtio-drivers,block,attest \
     TEST_IN_SVSM_SCRIPT=./scripts/test-in-svsm-attest.sh \
     TEST_IN_SVSM_DEPS=aproxy \
     test-in-svsm
```

You can replace `KBS_TEST_DIR` with `KBS_TEST_BIN=/path/to/kbs-test` if you
already have a `kbs-test` binary built.

The test will:
1. Start a local `kbs-test` server
2. Start an `aproxy` instance
3. Run the SVSM tests with attestation enabled
4. Verify "attestation successful" appears in the output

## Miri

Miri is an Undefined Behavior detection tool for Rust. It can run binaries and
test suites of cargo projects and detect unsafe code that fails to uphold its
safety requirements. For more information, see the
[project repository](https://github.com/rust-lang/miri).

Note that not all tests that are available under `cargo test` will be available
under Miri, as Miri cannot handle certain pieces of code, like inline assembly
blocks.

### Requirements

Miri only works with the nightly toolchain, e.g.

```shell
rustup toolchain install nightly
rustup +nightly target add x86_64-unknown-none
```

Then, Miri can be installed:

```shell
rustup +nightly component add miri
```

### Running

```shell
MIRIFLAGS=-Zmiri-permissive-provenance cargo +nightly miri test --workspace
# or
make miri
```

**NOTE**: Miri is *really* slow. The full test suite may take well over 30
minutes to complete.
