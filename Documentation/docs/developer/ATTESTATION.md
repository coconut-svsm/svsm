# Attestation

<!--toc:start-->
- [Attestation](#attestation)
  - [Background](#background)
  - [Attestation Phases](#attestation-phases)
    - [Negotiation Phase](#negotiation-phase)
    - [Attestation Phase](#attestation-phase)
  - [Attestation Host Proxy](#attestation-host-proxy)
    - [Frontend](#frontend)
    - [Backend](#backend)
    - [Host Proxy Diagram](#host-proxy-diagram)
  - [Transport Methods](#transport-methods)
  - [Try for yourself](#try-for-yourself)
<!--toc:end-->

## Background

To unlock early persistent state in SVSM (for example, persistent vTPM data), an
attestation of the launch environment must take place to ensure that SVSM is
running on trusted hardware and launched correctly. As SVSM does not have a
network stack available, a proxy runs on the host that facilitates attestation
between SVSM and a remote verification server such as KBS.

## Attestation Phases

There exists two consecutive phases of attestation:

### Negotiation Phase

Attestation servers usually require that a client embed metadata into its
attestation evidence. The negotiation phase (initiated by SVSM) defines what
exactly should be included in TEE attestation evidence. For instance, a server
may require that a client embed a nonce hash and public components of the TEE
public key (used to encrypt secrets) into the attestation evidence to ensure it
is fresh and legitimate. The negotiation phase returns the parameters that SVSM
should include in its attestation evidence based on the underlying attestation
server and protocol.

### Attestation Phase

With all relevant data embedded in TEE evidence, SVSM sends its evidence to the
remote server for evaluation. Upon successful attestation, the proxy will obtain
an encrypted secret (only decryptable by SVSM's TEE private key) for SVSM to
use. For example, SVSM could use this secret to unlock encrypted persistent
storage.

## Attestation Host Proxy

As there exists multiple protocols for TEE attestation, the host proxy is built
to be configurable to different protocols. As such, SVSM can be completely
agnostic of the attestation protocol used. This is done by separating the proxy
into two main components:

### Frontend

To keep SVSM agnostic to the underlying attestation protocol, a front-end
interface between SVSM and the proxy is defined. The types of this interface for
both negotiation and attestation are defined in the `libaproxy` crate. In the
negotiation phase, SVSM will write a `NegotiationRequest` and receive a
`NegotiationResponse` from the proxy. In the attestation phase, SVSM will write
an `AttestationRequest` and receive an `AttestationResponse` from the proxy.
This allows SVSM to not be exclusive to one specific attestation protocol,
leaving the possibility for new protocols to be enabled in the future (for
example, aTLS).

### Backend

The back-end implements the specific attestation protocol that the communicating
server implements. It is configurable with the `--backend` argument within
launching the proxy. The supported backend attestation protocols include:

- Key Broker Server (KBS)

### Host Proxy Diagram

```text
                                          ┌───────────┐
┌────┐               ┌─────┐              │Attestation│
│SVSM│◄─────────────►│Proxy│◄────────────►│Server     │
└────┘               └─────┘              └───────────┘
      │             │       │            │
      └─────────────┘       └────────────┘
         FRONT-END             BACK-END
       (independent          (dependent
       of attestation        on attestation
       server)               server and
                             protocol)
```

## Transport Methods

SVSM communicates with the attestation proxy using one of two transport methods:

- **vsock**: When the `vsock` feature is enabled, SVSM will first try to use vsock for communication with the host proxy
  using port `1995`. If it fails, SVSM will try again using the serial port.

- **Serial port**: If vsock is not available, SVSM uses the COM3 serial port for communication with the attestation proxy.

## Try for yourself

Please keep in mind that the attestation services in SVSM are **experimental**
at present.

To try for yourself, we provide a test KBS server that requires no configuration
and simply indicates if attestation was successful or not. This requires a
SEV-SNP machine with an SVSM-enabled kernel.

1. Clone and run the `kbs-test` server used for testing. Supply the following
   argument on the command line:

    * `--measurement`: hex-encoded expected launch measurement (64 bytes in size).

    ```shell
    # SVSM=<path to your Coconut SVSM directory>
    git clone https://github.com/coconut-svsm/kbs-test.git
    cd kbs-test
    MEASUREMENT="$(${SVSM}/bin/igvmmeasure --check-kvm ${SVSM}/bin/coconut-qemu.igvm measure -b)"
    HEX_EXPECTED_MEASUREMENT="$(echo $MEASUREMENT | xxd -p)"
    cargo run -- --measurement $HEX_EXPECTED_MEASUREMENT
    ```
    This will run the `kbs-test` server at <http://0.0.0.0:8080>.

2. Clone and build SVSM

    ```shell
    git clone https://github.com/coconut-svsm/svsm.git
    # ... build OVMF, qemu, SVSM IGVM, etc...
    FW_FILE=... make FEATURES=attest
    ```

3. Run the proxy on the host

    The proxy configuration depends on the transport mechanism:

    Common parameters:

    * `--url http://0.0.0.0:8080`: The attestation server is running at `http://0.0.0.0:8080`.
    * `--protocol kbs-test`: The attestation server communicates via the KBS
        protocol, configure the backend to use the KBS protocol.

    **vsock parameters**
    ```shell
    cd svsm
    make aproxy
    bin/aproxy --protocol kbs-test \
                --url http://0.0.0.0:8080 \
                --vsock-port 1995
    ```

    * `--vsock-port 1995`: Listen for messages from SVSM on the vsock port `1995`, which is
    the port used by SVSM for attestation.

    **Serial Port parameters**
    ```shell
    cd svsm
    make aproxy
    bin/aproxy --protocol kbs-test \
              --url http://0.0.0.0:8080 \
              --unix /tmp/svsm-proxy.sock \
              --force
    ```

    * `--unix /tmp/svsm-proxy.sock`: Listen for messages from SVSM on a socket
      created in file `/tmp/svsm-proxy-sock`.
    * `--force`: Remove the `/tmp/svsm-proxy.sock` file (if it already exists)
      before creating the socket.

4. Run a guest with SVSM

    SVSM will use vsock for communication if the feature is enabled, otherwise it
    falls back to the COM3 serial port (see [Transport Methods](#transport-methods)).
    The attestation proxy will need to be configured correctly to ensure proper communication
    according to the transport used.

    * **vsock**
      ```shell
      ./scripts/launch_guest.sh --qemu $QEMU \
                                --image $QCOW2 \
                                --vsock 3
      ```

    * **Serial Port**
      ```shell
      ./scripts/launch_guest.sh --qemu $QEMU \
                                --image $QCOW2 \
                                --aproxy /tmp/svsm-proxy.sock
      ```

    If successful, you should be able to find a message indicating a successful
    attestation within the SVSM boot logs.

    ```text
    [SVSM] attestation successful
    ```

    If unsuccessful, you should see a failure message within the SVSM boot logs:

    ```text
    [SVSM] ERROR: Panic on CPU[0]! COCONUT-SVSM Version: e48a1c14
    [SVSM] ERROR: Info: panicked at kernel/src/svsm.rs:349:36:
    called `Result::unwrap()` on an `Err` value: TeeAttestation(Failed)
    [SVSM] ---BACKTRACE---:
    [SVSM]   [ffffff80001c7976]
    [SVSM]   [ffffff800000497e]
    [SVSM]   [ffffff80000c3ad6]
    [SVSM]   [ffffff80000c3ae0]
    [SVSM] ---END---
    ```

    This likely is a result of the expected launch measurement not matching the
    actual launch measurement provided in the attestation report. In this case,
    attestation **should** fail.

    If so, the following message will be printed by the server (example):

    ```text
    launch measurement not as expected
    expected:"ef638e43239d319025e23c766c440c6f3e51660c2960bfc7045d30aee840f3981b15e4db8c6c7395dcdda91d005c6fe9"
    found:"9ef6c500d19addcd5937c6c8bd4e51b1893f048eea03d5407cfb0692c06615e3f6c044c667c32e520913d93234e836fe"
    ```

    Restart the server process giving the `found` launch measurement in the
    `--measurement` argument (indicating that this is now the **expected** launch
    measurement), then re-run qemu. In the previous example:

    ```shell
    cd kbs-test
    cargo run -- --measurement 9ef6c500d19addcd5937c6c8bd4e51b1893f048eea03d5407cfb0692c06615e3f6c044c667c32e520913d93234e836fe
    ```
