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
    "version": [0,1,0],
    "tee": "snp",
}
```

- `version`: The SVSM attestation protocol version to use. In place to ensure
backwards compatibility with updated protocol versions should modifications
occur. The API follows [SemVer](https://semver.org/) and is represented as a
tuple [MAJOR, MINOR, PATCH]. The current version is 0.1.0.
- `tee`: The TEE hardware architecture that SVSM is running on.

The proxy will then complete the negotiation phase with the remote attestation
server and reply with a list of negotiation parameters that must be included in
the attestation evidence.

A `NegotiationResponse` is sent from the proxy to SVSM.
An example `NegotiationResponse` is shown below.
```json
{
    "challenge": "oFlY92ZdS3ymzxokYuDzxw==\",
    "params": [
                "EcPublicKeyBytes",
                "Challenge"
              ]
}
```
- `challenge`: The challenge nonce returned by the remote attestation server
that will likely need to be hashed into the attestation evidence to ensure
freshness. Represented as variably-sized array of bytes.
- `params`: The negotiation parameters. Each `NegotiationParam` represents some
form of data that must be hashed into the attestation evidence. This hash will
be reconstructed by the remote attestation server when the evidence is presented
from SVSM.

The valid negotiation parameters are as follows:
- `Challenge`: The bytes represented in the `challenge`.
- `EcPublicKeyBytes`: The byte buffers of the public key's x and y coordinates
(in that order).

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
            "report": "AwAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAEAAAADAAAAAAAY0QUAAAAAAAAAAAAAAAAAAAAHZTCHj6
                       luB8MACrYnlqNmLuBgdclkh4UqGAMdZfMHZ+uVHytFLnvJXLkPx3xMf8p
                       B7faGTY+Mlwi96geujAbfPKa1C+9Kt7Hts/t0Vp+TKQachyjYCZLBhTV2
                       f7zI05r0HlwonTiV/mva7ZwxvdGaAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAACcdt0ZPBJrpXFX6RTFjSItibRTVsXM
                       Rn/pL/wbViPO6///////////////////////////////////////////A
                       wAAAAAAF9EZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAACd3vUWsdS5AAdRkM
                       51mXGLWEdB7w3CkS2L4/AmeQQPCKQFLcC81HJoD2st3/01IHaqOwGz3Xd
                       Lb57uqDPWYLxpAwAAAAAAGNEdNwEAHTcBAAMAAAAAABjRAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+InMMSLac18ai1bi
                       1kJZISAv0MXt7fBB9do732UwrcjUaxCNxZun8fsAWKXU1LPcAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAz+KTpyaINiKXdTAYhGTMl+g05It+QVEsrZ
                       5Vc1LHpng+KO4uFLFw0PLiXbNTwGU8AAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",
            "certs_buf": null
        }
    },
    "challenge": "oFlY92ZdS3ymzxokYuDzxw==\",
    "key":{
        "x": "AeFSAOU2/rtNV4VS0uTr5M729jAU1RIZ+p90kRRbIac6x56y40bG39gc+oxykTITDL
              gQER79+kVluCC+Lt6QSfaU\",
        "y": "AcBKVeKrw0p+7Nv/JuZMn+zuuQAhpSawoRq3g6Rhc9soXzsPlVLblIEw9muXSNUWbv
              fNrLHrmw+qy8lR1o/Kvkys\"
    }
}
```

- `tee`: The TEE architecture that the evidence should be interpreted as.
- `evidence`: The attestation evidence (i.e. report) from the TEE processor.
Based on the underlying TEE architecture (SEV-SNP being represented in the
example).

Valid evidence formats are the following:
- `Snp`: SEV-SNP
    - `report`: Attestation report bytes.
    - `certs_buf`: Optional byte buffer representing SEV-SNP certificate chain
                   (ARK, ASK, VEK) set by the host hypervisor.

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
    "secret": "aQ8Kt1EqRlj54Me3\",
    "decryption":{
        "epk":{
            "x": "AeFSAOU2/rtNV4VS0uTr5M729jAU1RIZ+p90kRRbIac6x56y40bG39gc+oxykT
                  ITDLgQER79+kVluCC+Lt6QSfaU\",
            "y": "ASrjxo2XfkkkNTiq174Uhj++eNgwzt1iA/hRrYA/6tn8i4ZgPjIiBT0EybAvn8
                  p3JQQmw6QKM38Ck5saMZcWF/4/\"
        },
        "wrapped_cek": "wucVMB63/N1jXTtIwF8WIbMU88X2NicJKwkyTX6eE4M4Fu1ZLcLIyA==\",
        "aad": "ZXlKaGJHY2lPaUpGUTBSSUxVVlRLMEV5TlRaTFZ5SXNJbVZ1WXlJNklrRXlOVFpI
                UTAwaUxDSmxjR3NpT25zaVkzSjJJam9pVUMwMU1qRWlMQ0pyZEhraU9pSkZReUlz
                SW5naU9pSkJaVVpUUVU5Vk1sOXlkRTVXTkZaVE1IVlVjalZOTnpJNWFrRlZNVkpK
                V2kxd09UQnJVbEppU1dGak5uZzFObmswTUdKSE16bG5ZeTF2ZUhsclZFbFVSRXhu
                VVVWU056a3RhMVpzZFVORExVeDBObEZUWm1GVklpd2llU0k2SWtGVGNtcDRiekpZ
                Wm10cmEwNVVhWEV4TnpSVmFHb3RMV1ZPWjNkNmRERnBRVjlvVW5KWlFWODJkRzQ0
                YVRSYVoxQnFTV2xDVkRCRmVXSkJkbTQ0Y0ROS1VWRnRkelpSUzAwek9FTnJOWE5o
                VFZwalYwWmZORjhpZlgw\",
        "iv": "Aqy5VLobeoLXAdiq\",
        "tag": "FKsIBoVn03SsONln0y66sw==\"
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

1. Clone and run the `kbs-test` server used for testing. Supply the following
   argument on the command line:

    * `--measurement`: hex-encoded expected launch measurement (64 bytes in size).

    ```shell
    # SVSM=<path to your Coconut SVSM directory>
    git clone https://github.com/coconut-svsm/kbs-test.git
    cd kbs-test
    MEASUREMENT="$(${SVSM}/bin/igvmmeasure --check-kvm ${SVSM}/bin/coconut-qemu.igvm measure -b)"
    cargo run -- --measurement $MEASUREMENT --secret $HEX_SECRET
    ```
    This will run the `kbs-test` server at <http://0.0.0.0:8080>.

2. Clone and build SVSM

    ```shell
    git clone https://github.com/coconut-svsm/svsm.git
    # ... build OVMF, qemu, SVSM IGVM, etc...
    FW_FILE=... make FEATURES=attest
    ```

3. Run the proxy on the host

    ```shell
    cd svsm
    make aproxy
    bin/aproxy --protocol kbs \
               --url http://0.0.0.0:8080 \
               --unix /tmp/svsm-proxy.sock \
               --force
    ```
    This runs the proxy with the following specified in the arguments:

     * `--url http://0.0.0.0:8080`: The attestation server is running at
       `http://0.0.0.0:8080`.
     * `--protocol kbs-test`: The attestation server communicates via the KBS
       protocol, configure the backend to use the KBS protocol.
     * `--unix /tmp/svsm-proxy.sock`: Listen for messages from SVSM on a socket
       created in file `/tmp/svsm-proxy-sock`.
     * `--force`: Remove the `/tmp/svsm-proxy.sock` file (if it already exists)
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
