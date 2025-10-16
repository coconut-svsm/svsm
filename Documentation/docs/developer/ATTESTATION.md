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

In the negotiation phase, a `NegotiationRequest` is sent from SVSM to the proxy.
An example `NegotiationRequest` is shown below.
```json
{
    "version": "0.1.0",
    "tee": "snp",
}
```

- `version`: The SVSM attestation protocol version to use. In place to ensure
backwards compatibility with updated protocol versions should modifications
occur. The API follows [SemVer](https://semver.org/).
- `tee`: The TEE hardware architecture that SVSM is running on.

The proxy will then complete the negotiation phase with the remote attestation
server and reply with a list of negotiation parameters that must be included in
the attestation evidence.

A `NegotiationResponse` is sent from the proxy to SVSM.
An example `NegotiationResponse` is shown below.
```json
{
    "challenge": [93,11,16,123,114,198,71,58,163,70,55,25,15,84,35,45],
    "params": [
                "EcPublicKeyBytes",
                "Challenge"
              ]
}
```
- `challenge`: The challenge nonce returned by the remote attestation server
that will likely need to be hashed into the attestation evidence to ensure
freshness.
- `params`: The negotiation parameters. Each `NegotiationParam` represents some
form of data that must be hashed into the attestation evidence. This hash will
be reconstructed by the remote attestation server when the evidence is presented
from SVSM.

SVSM can then collect the attestation evidence (with the negotiation parameters
embedded within the report data) and continue to the attestation phase.

### Attestation Phase

With all relevant data embedded in the TEE evidence, SVSM sends the evidence to
the remote server for evaluation. Upon successful attestation, the proxy will
obtain an encrypted secret (only decryptable by SVSM's attestation private key)
for SVSM to use. For example, SVSM could use this secret to unlock encrypted
storage.

In the attestation phase, an `AttestationRequest` is sent from SVSM to the proxy.
An example `AttestationRequest` is shown below.
```json
{
    "tee": "snp",
    "evidence":{
        "Snp":{
            "report": [$SEV-SNP-REPORT-BYTES],
            "certs_buf": null
        }
    },
    "challenge": [93,11,16,123,114,198,71,58,163,70,55,25,15,84,35,45],
    "key":{
        "x": [1,208,233,42,140,148,96,21,171,52,75,93,208,212,66,34,228,169,41,
              200,177,235,216,46,99,247,185,253,204,80,106,88,194,178,2,12,235,
              91,86,142,216,43,163,47,154,243,215,38,164,190,101,225,224,70,180,
              106,207,25,151,154,180,73,223,255,91,61],
        "y": [0,186,247,147,40,49,92,28,8,193,191,16,180,208,124,243,227,99,25,
              47,228,14,235,111,12,13,93,139,140,104,21,2,144,190,43,16,43,13,
              205,58,142,200,48,36,182,221,138,88,75,49,205,13,151,18,189,127,
              112,217,20,38,149,19,232,114,155,125]
    }
}
```

- `tee`: The TEE architecture that the evidence should be interpreted as.
- `evidence`: The attestation evidence (i.e. report) from the TEE processor.
Based on the underlying TEE architecture (SEV-SNP being represented in the
example).
- `challenge`: The original challenge nonce given in the `NegotiationResponse`.
- `key`: The EC public key that will be used to encrypt secret payloads received
from the remote server upon a successful attestation. Public key x and y
coordinates supplied.

The proxy will forward the evidence and metadata to the remote attestation
server for evaluation. Upon successful attestation, the proxy should be able to
retrieve some secret payload from the remote server. The proxy will retrieve
this secret and reply to SVSM with an `AttestationResponse`.
An example `AttestationResponse` is shown below.
```json
{
    "success": true,
    "secret": [198,102,83,251,55,253,210,235,237,118,23,89],
    "decryption":{
        "epk":{
            "x":[1,95,8,128,213,15,40,179,138,81,40,224,204,9,244,120,161,171,
                 77,247,182,253,40,44,139,167,14,93,10,192,115,243,31,92,247,
                 153,128,159,51,28,31,29,98,170,205,153,3,227,175,236,195,11,5,
                 149,220,128,12,43,39,53,3,236,107,227,201,110],
            "y":[0,170,175,77,27,25,112,249,44,31,214,71,255,20,83,226,147,250,
                 248,106,35,169,144,42,246,95,4,124,81,152,126,115,55,176,237,
                 142,5,232,212,13,83,245,204,214,77,36,67,155,227,50,145,139,57,
                 177,65,254,99,92,186,179,5,138,64,54,170,245]
        },
        "wrapped_cek":[22,126,164,68,101,129,98,97,46,18,192,141,216,131,93,119,
                       35,227,240,36,173,165,96,136,183,24,118,193,166,205,36,
                       173,230,19,104,52,38,154,236,57],
        "aad":[101,121,74,104,98,71,99,105,79,105,74,70,81,48,82,73,76,85,86,84,
               75,48,69,121,78,84,90,76,86,121,73,115,73,109,86,117,89,121,73,
               54,73,107,69,121,78,84,90,72,81,48,48,105,76,67,74,108,99,71,115,
               105,79,110,115,105,89,51,74,50,73,106,111,105,85,67,48,49,77,106,
               69,105,76,67,74,114,100,72,107,105,79,105,74,70,81,121,73,115,73,
               110,103,105,79,105,74,66,86,106,104,74,90,48,53,86,85,69,116,77,
               84,48,116,86,85,50,112,110,101,107,70,117,77,71,86,76,82,51,74,
               85,90,109,85,121,88,49,78,110,99,50,107,50,89,48,57,89,85,88,74,
               66,89,49,57,78,90,108,104,81,90,86,112,110,83,106,104,54,83,69,
               73,52,90,70,108,120,99,107,53,116,85,86,66,113,99,105,49,54,82,
               69,78,51,86,49,89,122,83,85,70,78,83,51,108,106,77,85,69,116,101,
               72,73,48,79,71,120,49,73,105,119,105,101,83,73,54,73,107,70,76,
               99,88,90,85,85,110,78,97,89,49,66,114,99,48,103,53,87,107,104,
               102,101,70,74,85,78,72,66,81,78,105,49,72,98,50,112,120,87,107,
               70,120,79,87,119,52,82,87,90,71,82,49,108,109,98,107,48,122,99,
               48,56,121,84,48,74,108,97,108,86,69,86,108,65,120,101,107,53,97,
               84,107,112,70,84,50,73,48,101,107,116,83,97,88,112,116,101,70,70,
               109,78,87,112,89,84,72,70,54,81,108,108,119,81,85,53,120,99,106,
               69,105,102,88,48],
        "iv":[74,131,36,224,204,41,89,237,217,125,139,21],
        "tag":[171,247,224,98,73,117,75,48,112,27,125,47,55,197,105,205]
    },
    "token":{
        "Jwt":"test-token"
    }
}
```
- `success`: Indicates if attestation was ultimately successful.
- `secret`: The encrypted secret payload.
- `decryption`: ECDH-ES-A256KW data needed to perform the handshake and derive
the AES key for the encrypted payload. Data is formatted for decryption with
ECDH-ES+A256KW, described in RFC 7518, section 4.6.2.
- `token`: Token returned from server that contains the claims validated in the
attestation. Could be serialized in JSON (JWT) or CBOR (CWT).

With a successful attestation, SVSM can now use the secret payload for some
purpose (for example, to unlock some persistent state required for booting the
OS) and continue with execution.

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

## Try for yourself

Please keep in mind that the attestation services in SVSM are **experimental**
at present.

To try for yourself, we provide a test KBS server that requires no configuration
and simply indicates if attestation was successful or not. This requires a
SEV-SNP machine with an SVSM-enabled kernel.

1. Clone and run the `kbs-test` server used for testing. Supply two arguments
   on the command line:

   `--measurement`: hex-encoded expected launch measurement (64 bytes in size).

    ```shell
    # SVSM=<path to your Coconut SVSM directory>
    git clone https://github.com/coconut-svsm/kbs-test.git
    cd kbs-test
    MEASUREMENT="$(${SVSM}/bin/igvmmeasure --check-kvm ${SVSM}/bin/coconut-qemu.igvm measure -b)"
    HEX_EXPECTED_MEASUREMENT="$(echo $MEASUREMENT | xxd -p)"
    cargo run -- --measurement $HEX_EXPECTED_MEASUREMENT --secret $HEX_SECRET
    ```

    This will run the `kbs-test` server at <http://0.0.0.0:8080>.

2. Clone and build SVSM

    ```text
    $ git clone https://github.com/coconut-svsm/svsm.git
    
    ... build OVMF, qemu, SVSM IGVM, etc...
    
    $ FW_FILE=... make FEATURES=attest
    ```

3. Run the proxy on the host

   ```shell
   cd svsm
   make aproxy
   bin/aproxy --protocol kbs-test \ 
              --url http://0.0.0.0:8080 \
              --unix /tmp/svsm-proxy.sock \
              --force
   ```

   This runs the proxy with the following specified in the arguments:

   - `--url http://0.0.0.0:8080`: The attestation server is running at
     `http://0.0.0.0:8080`.
   - `--protocol kbs-test`: The attestation server communicates via the KBS
     protocol, configure the backend to use the KBS protocol.
   - `--unix /tmp/svsm-proxy.sock`: Listen for messages from SVSM on a socket
     created in file `/tmp/svsm-proxy-sock`.
   - `--force`: Remove the `/tmp/svsm-proxy.sock` file (if it already exists)
     before creating the socket.

4. Run a guest with SVSM

   Initially, SVSM communicates over the COM3 serial port. The attestation proxy
   socket will need to be available in the correct `-serial` argument position to
   ensure it communicates with the right socket.

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
