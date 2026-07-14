# Attestation in SVSM using Trustee KBS

We need,
1. SVSM (with attest feature),
    > git clone https://github.com/coconut-svsm/svsm.git
2. The aproxy on the host.
3. Trustee KBS server (For now, the KBS softhsm container, is not upstream)
    > git clone https://github.com/armenon-rh/trustee.git

This document explains the steps to perform a complete attestation.

# Prerequisites & Architectural Overview
The Key Broker Service (KBS) handles confidential computing attestation and secret provisioning. Depending on your security requirements, it can be deployed in one of the two modes:

## Mode A: Resource Key-Value Storage Backend (Default)
Act as a direct storage repository for secrets.
- Flow: SVSM <--> aproxy <--> KBS (Resource kvstorage backend)
- Concept: The user provisions a secret into the KBS storage via kbs-client. SVSM later presents its attestation token to retrieve that raw secret.

## Mode B: PKCS#11 Plugin Backend (softHSM)
Offloads cryptographic operations and key management to a Software HSM.
- Flow: SVSM <--> aproxy <--> KBS(PKCS#11 plugin) <--> softHSM
- Concept: The user generates a 32-byte symmetric key, which softHSM wraps (encrypts) using its internal public key. The user uses the raw key to encrypt vTPM state, but implants the wrapped key into the metadata header. During boot, SVSM hands the wrapped key to KBS, which requests softHSM to unwrap it, passing back the raw key only after attestation.

# Step by Step implementation

## 1. Build the image

An Ubuntu based KBS container image that also has softHSM and opensc (pkcs11-tool to interact with softHSM) packages installed.

```bash
cd trustee/
podman build -t kbs-service -f kbs/docker/kbs-softhsm-pkcs11/Dockerfile .
```

## 2. Initialize Host storage directories

Create the required host workspaces to persist softHSM tokens and KBS resource assets

```bash
mkdir -p $HOME/kbs-workspace/softhsm_tokens
mkdir -p $HOME/kbs-workspace/kbs-storage
```

## 3. Configure Attestation Policy
Create the repository directory and establish the Open Policy Agent (OPA) Rego policy file that dictates KBS access rules.

```bash
mkdir -p kbs-workspace/repository/kbs && cd kbs-workspace/repository/kbs

cat <<EOF > resource-policy.rego
package policy

default allow = false

allow if {
    true
}
EOF

cd -
```

## 4. Run the KBS container
Choose the configuration profile that fits your desired operational mode:

### Option A: Run as Resource Backend (KV Storage)

```bash
podman run -d \
    --name kbs-pkcs11-service \
    -p 8080:8080 \
    -v $HOME/kbs-workspace/repository/kbs/resource-policy.rego:/etc/kbs/repository/kbs/resource-policy.rego:Z \
    -v $HOME/kbs-workspace/kbs-storage/:/opt/confidential-containers/storage:Z \
    kbs-service:latest /usr/local/bin/kbs --config-file /etc/kbs/kbs-config-resource.toml
```

### Option B: Run as PKCS#11 Plugin Backend
```bash
podman run -d \
    --name kbs-resource-service \
    -p 8080:8080 \
    -v $HOME/kbs-workspace/softhsm_tokens/:/var/lib/softhsm/tokens:Z \
    -v $HOME/kbs-workspace/repository/kbs/resource-policy.rego:/etc/kbs/repository/kbs/resource-policy.rego:Z \
    -v $HOME/test/trustee/kbs/docker/kbs-softhsm-pkcs11/config_pkcs11.toml:/etc/kbs/kbs-config.toml \
    kbs-service:latest
```

## 5. Generate Cryptographic assets
```bash
openssl rand 32 > rand.bin
echo "My secret" > secret.txt
```
The secret will be stored in kbs resource backend, whereas if we want to use the pkcs11 plugin then the key will be wrapped.

## 6. Provision or Wrap the cryptographic assets

### Option A: Store Secret in Resource Backend

```bash
make -C kbs cli FEATURES
./target/release/kbs-client --url http://0.0.0.0:8080 config  set-resource --path default/sample/test --resource-file secret.txt
```
The secret will be store in KBS.

### Option B: Wrap Key via PKCS#11 Plugin
```bash
curl -X POST http://0.0.0.0:8080/kbs/v0/pkcs11/wrap-key \
     -H "Content-Type: application/octet-stream" \
     --data-binary @rand.bin \
     --output wrapped_rand.bin
```
wrapped_rand.bin will contain the wrapped key

## 7. Use [tpm provisioner](https://github.com/armenon-rh/tpm_provisioner) to create an NVChip file

```bash
cd ../
git clone https://github.com/armenon-rh/tpm_provisioner.git && cd tpm_provisioner

podman build -t tpm-provisioner -f Dockerfile .

podman run -it --name tpm-lab tpm-provisioner

cargo run && verify

# Generate the ek public key from tpm, store it in ek.pub --> 1
tpm2_createek -T mssim:host=localhost,port=2321 -c ek.ctx -u ek.pub -G rsa

# print the public part of it the endorsement key  --> 2
tpm2_print -t TPM2B_PUBLIC ek.pub

# Retrieve the certificate from nvram, in DER format --> 3
tpm2_nvread -T mssim:host=localhost,port=2321 -C o 0x1c00002 -o ek_cert.der

# Extract public key from certificate, in PEM format --> 4
openssl x509 -in ek_cert.der -inform DER -pubkey -noout > cert_key.pem

# print the public key, modulus will be printed --> 5
openssl rsa -pubin -in cert_key.pem -text -noout

# modulus in 2 and 5 should match!

# copy the important files to host
# ek_cert.der, ek_cert.pem, local_ca.pem, cert_key.pem, NVChip
podman cp tpm-lab:/app/tpm_provisioner/<file_name> /path/on/host/<file_name>

```

## 8. Use [vtpm-to-svsm-blk](https://github.com/armenon-rh/vtpm-to-svsm-blk) to create a virtio block image
- use rand.bin from step 5 as key for encryption param
- use wrapped_rand.bin from step 6 as wrapped key param
vtpm_state.img is ready, which has payload encrypted and a header with the wrapped key.

```bash
git clone https://github.com/armenon-rh/vtpm-to-svsm-blk.git && cd vtpm-to-svsm-blk

cargo build

cargo run -- -k rand.bin -w wrapped_rand.bin -s /path/on/host/<NVChip> -o /path/on/host/to/store/vtpm_state.img

# This will create a vTPM image, that can be attached to SVSM as a virtio block

```

## 9. Run Aproxy on the host

```bash
cd svsm/
make aproxy
./bin/aproxy --protocol kbs \
    --url http://0.0.0.0:8080 \
    --unix /tmp/svsm-proxy.sock \
    --force > aproxy.log 2>&1 &
```

## 10. Launch the confidential guest

Assuming that qemu is compiled using the [svsm](https://github.com/coconut-svsm/qemu.git) branch and SVSM is compiled using the latest [OVMF.FD file](https://github.com/coconut-svsm/edk2.git), and the fedora image is built using [image builder](https://github.com/stefano-garzarella/snp-svsm-vtpm/blob/main/build-vm-image.sh)

```bash
./scripts/launch_guest.sh --aproxy /tmp/svsm-proxy.sock \
    --qemu $HOME/test/qemu/bin/qemu-system-x86_64 \
    --image $HOME/test/snp-svsm-vtpm/images/fedora-luks.qcow2 \
    --state ../vtpm_state.img
```

Note: Make sure to add the option --pcd PcdUninstallMemAttrProtocol=TRUE while building edk2 for Fedora 42 images

```bash
export PYTHON3_ENABLE=TRUE
export PYTHON_COMMAND=python3
make -j16 -C BaseTools/
source ./edksetup.sh --reconfig
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 \
      -b DEBUG -t GCC \
      -D DEBUG_ON_SERIAL_PORT \
      -D DEBUG_VERBOSE \
      -D TPM2_ENABLE
      --pcd PcdUninstallMemAttrProtocol=TRUE
```