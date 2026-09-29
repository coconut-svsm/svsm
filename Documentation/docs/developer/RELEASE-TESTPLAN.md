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
./scripts/run-fuzzers.sh
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

### Attestation and Persistence Tests

Test persistence by unlocking the persistent state with a secret obtained from
KBS attestation over vsock. See [ATTESTATION.md](ATTESTATION.md) for full
details.

On success, the following messages appear in the boot logs:
```
[SVSM] attestation successful
[SVSM] persistent CocoonFs storage opened successfully
```

If attestation fails, SVSM will not unlock the persistent state, so services
cannot persist data across reboots (e.g. vTPM NV state).

#### Build SVSM, proxy, and igvmmeasure

```
cargo xbuild -f persistence configs/qemu-target.json
make aproxy bin/igvmmeasure
```

#### Create the state image and start the kbs-test server

In a separate terminal:

```
SVSM=/path/to/svsm
HEX_SECRET=793212d775af0b2a3e6186a9b701bfefd440d4a048e58fbac4240b913efb58f8

git clone https://github.com/coconut-svsm/cocoon-tpm.git
pushd cocoon-tpm
cargo run -p cocoonfs-cli -- -i "$SVSM/cocoonfs.img" -f mkfs -K $HEX_SECRET -H sha2 -C aes -t 128 -I 'ddeeff' -s 8M
popd

git clone https://github.com/coconut-svsm/kbs-test.git
cd kbs-test
MEASUREMENT="$($SVSM/bin/igvmmeasure --check-kvm $SVSM/bin/coconut-qemu.igvm measure -b)"
cargo run -- --measurement $MEASUREMENT --secret $HEX_SECRET
```

Start the proxy in another terminal:

```
bin/aproxy --protocol kbs --url http://0.0.0.0:8080 --vsock
```

#### Automatically mount encrypted rootfs with a stateful TPM

This test requires `$IMAGE` to have a LUKS-encrypted rootfs. `--snapshot off`
is required because `systemd-cryptenroll` stores the sealed key in the LUKS2
header of the guest image, which would otherwise be discarded at poweroff.
Note that this permanently modifies `$IMAGE`.

Launch the guest with an encrypted rootfs and seal the LUKS passphrase with
the TPM:

```
./scripts/launch_guest.sh --vsock 3 --state cocoonfs.img --snapshot off

# during the boot, enter the LUKS key to mount the root filesystem

guest$ systemd-cryptenroll /dev/sda3 --wipe-slot=tpm2
guest$ systemd-cryptenroll /dev/sda3 --tpm2-device=auto --tpm2-pcrs=0,1,4,5,7,9
guest$ poweroff
```

Restart the guest; the LUKS passphrase sealed with the TPM will automatically
decrypt the disk during the boot:

```
./scripts/launch_guest.sh --vsock 3 --state cocoonfs.img --snapshot off

# rootfs automatically mounted, the login prompt is displayed directly
```
