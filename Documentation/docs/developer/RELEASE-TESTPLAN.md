# Release Testplan

## Testplan for Monthly Development Releases

Here is the list of tests performed for each monthly development release.

### Environment Setup

Set the following environment variables before running the tests:

```
export FW_FILE=/usr/share/edk2/ovmf/OVMF.amdsev.fd
export QEMU=/path/to/qemu-system-x86_64
export IMAGE=/path/to/guest.qcow2
```

### Build all targets

Build all targets in the `configs/` directory.

```
cargo xbuild configs/*.json configs/test/*.json
```

### Development Build + SNP boot test

Build with debug flag enabled and boot VM under SEV-SNP to Linux prompt.

```
cargo xbuild configs/qemu-target.json
./scripts/launch_guest.sh
```

### Development Build + Native boot test

Build with debug flag enabled and boot COCONUT-SVSM in a non-confidential VM.

```
cargo xbuild configs/qemu-target.json
./scripts/launch_guest.sh --nocc
```

### Release Build + SNP boot test

Build with release flag enabled and boot VM under SEV-SNP to Linux prompt.

```
cargo xbuild --release configs/qemu-target.json
./scripts/launch_guest.sh
```

### Release Build + Native boot test

Build with release flag enabled and boot COCONUT-SVSM in a non-confidential VM.

```
cargo xbuild --release configs/qemu-target.json
./scripts/launch_guest.sh --nocc
```

### Fuzzers

Run all the fuzzers included in the project for an extended period of time.
Given that failures in the past usually showed up in the first minute of
fuzzing, for releases the fuzzer runs for a minimum of 10 minutes.

```
for target in $(cargo +nightly fuzz list); do
    echo "== Fuzzing: $target =="
    RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=lld" \
        cargo +nightly fuzz run $target --strip-dead-code -- -max_total_time=600 \
        || { echo "FAILED: $target"; break; }
done
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

### TPM Tests

Start a Linux guest OS

```
cargo xbuild configs/qemu-target.json
./scripts/launch_guest.sh
```

and run the following TPM2 tests:

#### Check TPM2 availability

```
systemd-analyze has-tpm2
```

#### Seal/Unseal

```
pushd $(mktemp -d)

SECRET="secret"
tpm2_createprimary -c primary.ctx

echo "sealing '$SECRET' without PCRs"
echo "$SECRET" | tpm2_create -C primary.ctx -i - -u seal.pub -r seal.priv
tpm2_load -C primary.ctx -u seal.pub -r seal.priv -c seal.ctx
unsealed=$(tpm2_unseal -c seal.ctx)
echo "unsealed: '$unsealed'"
[ "$unsealed" != "$SECRET" ] && echo "FAILED: unseal without PCRs: expected '$SECRET'" && false

echo "sealing '$SECRET' with PCRs"
tpm2_pcrread -Q -o pcr.bin sha256:0,1,2,3
tpm2_createpolicy --policy-pcr -l sha256:0,1,2,3 -f pcr.bin -L pcr.policy
echo "$SECRET" | tpm2_create -C primary.ctx -L pcr.policy -i - -u seal.pub -r seal.priv
tpm2_load -C primary.ctx -u seal.pub -r seal.priv -c seal.ctx
unsealed=$(tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3)
echo "unsealed: '$unsealed'"
[ "$unsealed" != "$SECRET" ] && echo "FAILED: unseal with PCRs: expected '$SECRET'" && false

popd
```

#### Self Test

```
tpm2_selftest -f
```

#### Event Log

Check that OVMF recorded EFI events in the TPM event log.

```
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | \
    grep EV_EFI_BOOT_SERVICES_APPLICATION || { echo "FAILED: no EFI boot services events"; false; }
```

#### vTPM Attestation

Test SEV-SNP vTPM service attestation via Linux configfs-tsm.

```
# Fedora/RHEL: dnf install -y git cargo tpm2-tss-devel
# Debian/Ubuntu: apt install -y git cargo libtss2-dev
# openSUSE/SUSE: zypper install -y git cargo tpm2-0-tss-devel
git clone https://github.com/hpe-security-lab/svsm-vtpm-test.git
cd svsm-vtpm-test
cargo run
```
