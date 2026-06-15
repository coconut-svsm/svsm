# Introduction

SVSM is an in-guest paravisor written in Rust and designed for secure
virtualization environments, primarily AMD SEV-SNP and Intel TDX. It operates
at the highest privilege level within the Confidential Virtual Machine (VMPL0
on SEV-SNP).

# Directory structure

The SVSM runs on bare metal as a ring-0 kernel, with optional userspace
components. Important directories:

* `kernel/`: main SVSM kernel
* `boot/`: kernel bootloader and definitions
* `syscall/`: SVSM kernel/userspace system call definitions
* `user/`: SVSM userspace library and example init process
* `tools/`: general tools

# Building and testing

The SVSM project is organized as a cargo workspace. Some workspace members
are built with the host toolchain and others are built for bare metal. Running
`cargo build` or `cargo test` will not necessarily work.

* Build: use `make`.
* Test: use `make test` for unit tests. Read
  `Documentation/docs/developer/TESTING.md`.
* Linter: run `make clippy`.
* Format checks: `cargo fmt --check` works as usual.

All of the above must run cleanly after making a set of changes. Additionally,
all `unsafe` blocks must have a `SAFETY` comment detailing why the code is safe
and/or what invariants are assumed.

Additional code documentation guidelines can be found at
`Documentation/docs/developer/RUSTDOC-GUIDELINES.md`.

## Build recipes

The project uses custom build tools to generate an image that may be loaded
by the hypervisor. The top-level orchestrator is the `xbuild` tool, which is
called from the Makefile. The recipes are located in `configs/`. Information
about the build recipe format can be found in
`Documentation/docs/installation/BUILD_RECIPES.md`.

## IGVM

IGVM is the image format that the build system generates and that the host
VMM accepts. It describes the memory contents of the guest at startup. The
SVSM generates the IGVM image via `tools/igvmbuilder`, which is orchestrated
by `xbuild`.

## Formal verification with Verus

This repository integrates formal verification using **Verus**.
* Verified source files end with `*.verus.rs` or `*.proof.verus.rs` (e.g.,
  `address.verus.rs`, `alloc_perms.verus.rs`).
* Verification Invariants: Never bypass, alter, or strip
  `#![cfg_attr(verus_keep_ghost, ...)]` blocks or Verus ghost specifications
  unless specifically instructed. Any structural change to a verified module
  requires re-verification by executing the Verus toolchain.
* If a compiler flag or configuration change is made, ensure the `verus` or
  `verus_all` feature configurations in `Cargo.toml` remain valid.
* Do not run any verification checks unless specifically asked OR if related
  code was updated.
* Usage documentation is found in `Documentation/docs/developer/VERIFICATION.md`.

## General coding guidelines

* Wrap accesses to guest memory with `GuestPtr`. This type makes sure that an
  access fault is handled and returned as a regular error.
* Be exceedingly careful when accessing guest and host-shared memory. In
  general, shared memory may contain any bit combination and can be updated at
  any moment. We use `FromBytes` to make sure a type has no invalid bitwise
  representations, and `Sync` to make sure that unsynchronized concurrent
  accesses do not break assumptions. Creating Rust references (`&T` / `&mut T`)
  to shared memory is never safe and must be avoided.

# Platform

This section describes the confidential computing platforms the SVSM runs on,
and their security model. The SVSM abstracts platform details under the
`SvsmPlatform` trait.

The host hypervisor (HV) is **untrusted**: it sits outside the Trusted
Computing Base (TCB) and can manipulate VMCB fields, intercept VM exits, and
control physical memory assignment, but it cannot read or tamper with encrypted
guest memory or forge attestation measurements.

Confidentiality and integrity are part of the security model, while availability
is not. The SVSM aims to be robust and stable, but panicking on invalid states
or unrecoverable conditions is allowed and expected.

## SVSM-guest communication

The SVSM provides services for the lower privilege guest via a shared memory
protocol. Guests request services by writing parameters to a shared memory
calling area and triggering a `VMGEXIT` (SEV-SNP) or a `TDVMCALL` (TDX) that
traps into SVSM at VMPL0 (or L1).

Each protocol has an ID, and each command available within that protocol has a
dedicated call ID. Supported protocols:

| ID | Name                  | Implementation                     | Purpose |
|----|-----------------------|------------------------------------|---------|
| 0  | Core Protocol         | `kernel/src/protocols/core.rs`     | Protocol discovery, memory validation requests (`PVALIDATE`), guest vCPU creation/deletion |
| 1  | Attestation Protocol  | `kernel/src/protocols/attest.rs`   | Provides attestation reports, signing certificates, and manifest querying |
| 2  | vTPM Protocol         | `kernel/src/protocols/vtpm.rs`     | Bridges simulated TPM commands to the TPM reference simulator |
| 3  | Virtual APIC Protocol | `kernel/src/protocols/apic.rs`     | Provides virtual local APIC registers, configuration, and vector settings |
| 4  | UEFI Management Mode  | `kernel/src/protocols/uefivars.rs` | Bridges UEFI MM communication requests to the variable store (`feature = "uefivars"`)

### Security Boundaries & Invariants

Because guest-to-SVSM requests originate from lower privilege levels, **every
argument and memory location passed by the guest must be treated as untrusted
and potentially hostile.**

* SVSM code must never dereference raw guest pointers directly. Any memory
  address (Guest Physical Address or GPA) provided by the guest must be wrapped
  in `GuestPtr<T>`.
* Always validate that guest-provided buffers do not cross page boundaries
  unless explicitly handled, as page boundaries may map to disparate physical
  ranges.
* For commands accepting length parameters (e.g., attestation report nonces,
  vTPM packets), explicitly check that sizes match fixed requirements (e.g.,
  `nonce_size == 64`) or do not exceed pre-allocated buffers (e.g.,
  `MAX_CERTIFICATE_SIZE` limits).
* Ensure guest buffers do not overlap with SVSM's own private memory space to
  prevent unauthorized memory modification or disclosure.
* To prevent Time-of-Check to Time-of-Use (TOCTOU) and race conditions when
  modifying guest state:
     * SVSM uses a dedicated reader-writer lock, **`PVALIDATE_LOCK`**, around
       state-changing operations.
     * The lock is acquired as **read** during validation
       (`SVSM_REQ_CORE_PVALIDATE`) and as **write** during operations
       that change guest vCPU context, VMSA pages, or Calling Areas
       (`SVSM_REQ_CORE_CREATE_VCPU`, deleting vCPUs, or updating VM structures).
     * Ensure any routine modifying guest CPU mappings or structures respects
       this locking hierarchy.

## Platform components (SEV-SNP)

### Reference Specifications

The following external specifications define the interfaces and hardware
mechanisms that the SVSM implements for SEV-SNP. When reviewing or modifying
protocol handlers, cross-check the code against the relevant spec section if
available.

* **AMD Pub #58019** (*Secure VM Service Module for SEV-SNP Guests*):
  defines the calling convention, result codes, and all protocol calls (Core,
  Attestation, vTPM, APIC Emulation, UEFI Management Mode).
* **AMD Pub #56421** (*SEV-ES Guest-Hypervisor Communication Block (GHCB)
  Standardization*): defines the GHCB page layout, MSR protocol, and NAE event
  handling.
* **AMD Pub #56860** (*SEV Secure Nested Paging Firmware ABI Specification*):
  defines RMP, PVALIDATE/RMPADJUST/RMPUPDATE instruction behavior, VMPL
  permission model, and SNP guest request message format.
* **AMD64 Architecture Programmer's Manual, Volume 2**: instruction
  reference for PVALIDATE, RMPADJUST, RMPUPDATE, VMGEXIT, and related SEV-SNP
  instructions.

### GHCB

The GHCB is a **shared (unencrypted) page** used to pass data between the guest
and the hypervisor during `VMGEXIT`. Because it is unencrypted and mapped by
the HV, **every field read from the GHCB must be treated as untrusted input**.

* GHCB fields require validation. The HV writes response data into the GHCB;
  validate that the SW_EXITINFO fields, MSR protocol responses, and NAE event
  data are within expected ranges before use.
* Scratch the GHCB before and after use. Clear sensitive fields after a
  VMGEXIT to avoid leaking data to a subsequent intercept.
* MSR protocol vs. full GHCB protocol: The MSR protocol (using
  `MSR_AMD64_SEV_ES_GHCB`) is used before the GHCB page is established; it has
  its own encoding and must be checked for protocol version compatibility. The
  GHCB page physical address is established via `GHCB_MSR_REG_GHCBxx`.
* Bitmap validity: the GHCB valid-bitmap tracks which fields the HV has
  populated. Only access fields that are marked valid.

### Memory Management

#### Reverse Map Table (RMP)

The RMP is a hardware mechanism to track the owner of every 4KB physical page.
It contains an entry for every physical page which tracks:

* Owner (which ASID / guest owns the page)
* VMPL permissions (read/write/execute per VMPL level)
* Validation state (validated / unvalidated)
* Page size (4 KB vs 2 MB)

#### Page state machine

Pages transition through a strict state machine. Violating the expected
transition causes a `#NPF` (nested page fault) or `RMPUPDATE` failure.

Relevant page states are:

| State         | Description                           | Notes                                                     |
|---------------|---------------------------------------|-----------------------------------------------------------|
| Hypervisor    | Default state for unassigned memory   | Used for hypervisor memory, non-SNP VMs and shared memory |
| Guest-invalid | Assigned to guest but not useable yet | Given by the hypervisor but not accepted by guest         |
| Guest-valid   | Assigned to guest and useable         | Page useable as private (C=1) by the assigned SNP VM.     |

Pages can be transitioned across states using the `PVALIDATE` and `RMPUPDATE`
instructions. Relevant page state transitions:

| Start state   | End state     | Mechanism |
|---------------|---------------|-----------|
| Hypervisor    | Guest-invalid | RMPUPDATE |
| Guest-invalid | Hypervisor    | RMPUPDATE |
| Guest-invalid | Guest-valid   | PVALIDATE |
| Guest-valid   | Hypervisor    | RMPUPDATE |

Critical invariants:

* **PVALIDATE before first use.** A page must be validated before the guest
  accesses it as private memory. Skipping this results in a fault.
* **RMPUPDATE is VMPL0-only.** Only SVSM (VMPL0) code may call `RMPUPDATE`.
  Auditing paths that reach `RMPUPDATE` from VMPL1 requests is a security
  boundary; validate all GPA and size arguments before proceeding.
* **VMPL permission bits.** `RMPADJUST` can grant or restrict VMPL1–3 access.
  SVSM controls which pages VMPL1 can write; never grant VMPL1 write access to
  SVSM's own code or data pages.
* **Aliasing attacks**: the RMP ensures in hardware that a physical memory page
  can map only to a single guest page at a time.
* **Remapping attacks**: the guest must never validate the same page twice.
  This opens an opportunity for the following attack:
    1. Guest PVALIDATEs a page, mapping GPA A to SPA X.
    2. Hypervisor allocates SPA Y by allocating an entry in the RMP and updating
       the nested page tables.
    3. Guest validates GPA A again. GPA A has been remapped from SPA X to Y.

#### Shared vs. private pages

* **Private pages** are encrypted with the guest's key; the HV sees ciphertext.
* **Shared pages** (C-bit=0) are readable by the HV — treat them as public.
  Never store secrets on shared pages. Never interpret shared-page contents as
  trusted without explicit integrity mechanisms.

### CPUID

A CPUID page is set up for the guest on boot by the platform. It is used by
the SVSM to query secure CPUID values without host hypervisor involvement.

### HV Doorbell page

The #HV (hypervisor injection) doorbell page is a shared page used by the
HV to signal pending events to SVSM/guest when the VM is running with
restricted injection enabled. The HV writes a flag into the doorbell page
rather than directly injecting an interrupt or exception.

Security properties

* The doorbell page is HV-controlled shared memory. Its contents are entirely
  attacker-controlled.
* SVSM must not act on doorbell flags without bounding the action. A malicious
  HV could set arbitrary flag combinations.
* The doorbell page address is communicated via the GHCB MSR protocol during
  setup. Validate that the registered GPA is the expected one; do not accept
  a redirect to an arbitrary page.
* After reading the doorbell, atomically clear the relevant bits before
  processing — this prevents the HV from re-signalling during handling to
  cause double-delivery.
* Doorbell processing code must be reentrant-safe: the HV could set the
  doorbell again while SVSM is in the middle of a previous doorbell handler.

### Interrupt security

#### Restricted Injection (`SEVStatusFlags::REST_INJ`)

* The HV cannot directly inject exceptions or interrupts into the guest.
* All events are delivered via the #HV exception, which traps into SVSM at
  VMPL0.
* SVSM acts as an interrupt controller proxy: it inspects HV-requested
  events, validates them, and decides whether to reflect them into the guest.
* Validation rules before reflecting an event into VMPL1+:
  * Vector must be in a permitted set (no injecting #GP, #PF, or #DF
   into the guest to confuse its exception handlers maliciously).
  * Error codes must be consistent with the vector.
  * CR2 (for #PF) must not be forged to redirect guest fault handling.

* Never reflect a #VC (#29) from HV into the guest. The #VC handler
  is security-sensitive and its activation must only come from genuine guest
  VMGEXIT paths.

#### Alternate Injection (`SEVStatusFlags::ALT_INJ`)

* The HV uses an alternate VMCB field for event injection rather than the
  standard EVENTINJ field.
* When alternate injection is enabled, the SVSM emulates a virtual APIC for
  the guest.
* SVSM must process and validate the alternate injection field on each
  #HV exit before forwarding.
* The threat is the same: HV-provided injection data is untrusted. Validate
  vector, type, error-code-valid bit, and error code before acting.

### VMSA (VM Save Area) Integrity

* The VMSA is a private, encrypted page holding vCPU register state. At
  VMPL0, SVSM can read/write VMSAs for lower VMPLs.
* When transitioning to a lower VMPL (via VMGEXIT VMPL switch), SVSM writes
  the target VMSA. Ensure that no HV-influenced data flows into
  security-sensitive VMSA fields (CS/SS DPL, EFER.SVME, CR0, CR4).
* The VMPL field in the VMSA is hardware-enforced; do not rely on software
  tracking of the current VMPL level without cross-checking hardware state.

## TDX

### Reference Specifications

* **Intel TDX Module ABI Specification**: Defines TDCALL/TDVMCALL leaf functions
  (`TDG.MEM.PAGE.ACCEPT`, `TDG.VP.VMCALL`, etc.).
* **Intel TDX Module TD Partitioning Architecture Specification**: Defines the
  ABI for the TDX Module's TD Partitioning feature.

### SEV-SNP comparison

* No VMPLs. TDX uses a scheme called TD Partitioning. SVSM runs as the L1 VM
  (equivalent of VMPL0), lower-privileged guest runs as L2 VM.
* TDCALL and TDVMCALL replace VMGEXIT. Both have different ABI conventions.
  * TDCALL exits to the TDX module.
  * TDVMCALL in L1 exits to the VMM.
  * TDVMCALL in L2 can be configured to exit either to L1 or VMM.
* Shared memory uses the GPA.S bit rather than the C-bit. GPA.S has the opposite
  meaning to the C-bit: pages with GPA.S=1 are shared with the VMM; treat
  them identically to SEV-SNP shared pages (fully untrusted). The position of
  the GPA.S bit is determined by bits `[5:0]` of RBX in the initial TD vCPU
  registers. The SVSM bootloader takes this value to determine a virtual top of
  memory (VTOM).
* No RMP / PVALIDATE. Pages are accepted with `TDCALL[TDG.MEM.PAGE.ACCEPT]`.
  There is no "unaccept" step on TDX. Accepted pages are converted between
  shared and private via `TDVMCALL[MAP_GPA]`.
* Interrupt injection is controlled by the VMM via posted interrupts and
  the TD-VMCS; there is no restricted-injection equivalent.
