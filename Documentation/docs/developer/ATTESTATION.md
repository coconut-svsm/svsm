# Background

To unlock early persistent state in SVSM (for example, persistent vTPM data), an
attestation of the launch environment must take place to ensure that SVSM is
running on trusted hardware and launched correctly. As SVSM does not have a
network stack available, a proxy runs on the host that facilitate attestation
between SVSM and a remote verification server such as KBS.

# Attestation Phases

There exists two consecutive phases of attestation:

## Negotiation

Attestation servers usually require that a client embed metadata into its
attestation evidence. The negotiation phase (initiated by SVSM) defines what
exactly should be included in TEE attestation evidence. For instance, a server
may require that a client embed a nonce hash and public components of the TEE
public key (used to encrypt secrets) into the attestation evidence to ensure it
is fresh and legitimate. The negotiation phase returns the parameters that SVSM
should include in its attestation evidence based on the underlying attestation
server and protocol.

## Attestation

With all relevant data embedded in TEE evidence, SVSM sends its evidence to the
remote server for evaluation. Upon successful attestation, the proxy will obtain
an encrypted secret (only decryptable by SVSM's TEE private key) for SVSM to
use. For example, SVSM could use this secret to unlock encrypted persistent
storage.

# Attestation Host Proxy

As there exists multiple protocols for TEE attestation, the host proxy is built
to be configurable to different protocols. As such, SVSM can be completely
agnostic of the attestation protocol used. This is done by separating the proxy
into two main components:

## Front-end

To keep SVSM agnostic to the underlying attestation protocol, a front-end
interface between SVSM and the proxy is defined. The types of this interface for
both negotiation and attestation are defined in the `libaproxy` crate. In the
negotiation phase, SVSM will write a `NegotiationRequest` and receive a
`NegotiationResponse` from the proxy. In the attestation phase, SVSM will write
an `AttestationRequest` and receive an `AttestationResponse` from the proxy.
This allows SVSM to not be exclusive to one specific attestation protocol,
leaving the possibility for new protocols to be enabled in the future (for
example, aTLS).

## Back-end

The back-end implements the specific attestation protocol that the communicating
server implements. It is configurable with the `--backend` argument when launching the
proxy. The supported backend attestation protocols include:

- Key Broker Server (KBS)

## Host Proxy Diagram

```
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

# Try for yourself

Please keep in mind that the attestation services in SVSM are **experimental**
at present.

To try for yourself, we provide a test KBS server that requires no configuration
and simply indicates if attestation was successful or not. This requires a
SEV-SNP machine with an SVSM-enabled kernel.

1. Clone and run the `kbs-test` server used for testing. Supply two arguments
   on the command line:

   `--measurement`: base64-encoded expected launch measurement (64 bytes in size).
   `--secret`: base64-encoded secret to be released upon successful attestation.

```
$ git clone https://github.com/coconut-svsm/kbs-test.git
$ cd kbs-test
$ MEASUREMENT="$(${SVSM}/bin/igvmmeasure --check-kvm ${SVSM}/bin/coconut-qemu.igvm measure -b)"
$ BASE64_EXPECTED_MEASUREMENT="$(echo $MEASUREMENT | xxd -r -p | base64 -w 0)"
$ BASE64_SECRET="$(echo HelloWorld | base64 -w 0)"
$ cargo run -- --measurement $BASE64_EXPECTED_MEASUREMENT --secret $BASE64_SECRET
```

Note that the `--secret` argument is unsued for this demo, but **can** be used
with small modifications.

This will run a the `kbs-test` server at http://0.0.0.0:8080.

2. Clone and build SVSM

```
$ git clone https://github.com/coconut-svsm/svsm.git

... build OVMF, qemu, SVSM IGVM, etc...

$ FW_FILE=... make FEATURES=attest
```

3. Run the proxy on the host

```
$ cd svsm
$ make aproxy
$ bin/aproxy --protocol kbs-test --url http://0.0.0.0:8080 --unix /tmp/svsm-proxy.sock --force
```

This runs the proxy with the following specified in the arguments:

- `--url http://0.0.0.0:8080`: The attestation server is running at `http://0.0.0.0:8080`.
- `--protocol kbs-test`: The attestation server communicates via the KBS protocol, configure the backend to use the KBS protocol.
- `--unix /tmp/svsm-proxy.sock`: Listen for messages from SVSM on a socket created in file `/tmp/svsm-proxy-sock`.
- `--force`: Remove the `/tmp/svsm-proxy.sock` file (if it already exists) before creating the socket.

4. Run a guest with SVSM

Initially, SVSM communicates over the COM3 serial port. The attestation proxy
socket will need to be available in the correct `-serial` argument position to
ensure it communicates with the right socket.

```
$ ./scripts/launch_guest.sh --qemu $QEMU --image $QCOW2 --aproxy /tmp/svsm-proxy.sock
```

If successful, you should be able to find a message indicating a successful
attestation within the SVSM boot logs.

```
[SVSM] attestation successful
```

If unsuccessful, you should see a failure message within the SVSM boot logs:

```
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
```
launch measurement not as expected
expected:"abcdaab+7GuPU52efdhq3PtvEcQpXl1lmnop75WQ1lzvgGz0Xmyyt9SSGoJImshp"
found:"fNcbjTk+7GuPU52wSQ6q3PtvEcQpXl1KXOzV75WQ1lzvgGz0Xmyyt9SSGoJImshp"
```

Restart the server process giving the `found` launch measurement in the
`--measurement` argument (indicating that this is now the **expected** launch
measurement), then re-run qemu. In the previous example:

```
$ cd kbs-test
$ cargo run -- --measurement fNcbjTk+7GuPU52wSQ6q3PtvEcQpXl1KXOzV75WQ1lzvgGz0Xmyyt9SSGoJImshp --secret $BASE64_SECRET
```
