# COCONUT-SVSM Development Plan

## First Principles of COCONUT-SVSM Design

The first section contains the overall principles applied when creating the
design of COCONUT-SVSM. The following sections break down known development
items and their dependencies to achieve these principles.

### Mission

The mission of COCONUT-SVSM is **be a platform to provide secure services to
Confidential Virtual Machines (CVMs)**. 

The services provided by COCONUT-SVSM aim to increase the security of the CVM by:

* Moving hypervisor services from the untrusted host into the trusted CVM context.
* Handle CVM specifics in the SVSM instead of the requiring additional support
  in the OS to reduce the attack surface of the guest operating system.

### Security

COCONUT-SVSM is one of the most critical parts in the security architecture of
a CVM. Therefore any design decisions have to take security implications into
account.

The main tool used to achieve better security properties within its own
code-base is *Isolation*. In particular, this means:

* Services provided to the CVM run as **user-mode processes** by default. Only
  when there are very good reasons parts or whole services can be implemented in
  the COCONUT kernel.
* Memory isolation within the COCONUT kernel. Provide per-CPU and per-Task
  memory which is not accessible outside of its context.
* Cryptographic isolation: Isolate the cryptographic code and data (keys) from
  the rest of the system and between contexts.

### Execution Modes

The COCONUT-SVSM platform aims to support three execution modes:

* **Enlightened OS mode**: In this mode the guest OS is aware of the
  environment and can handle most CVM specifics itself. The guest OS has a VE/VC
  exception handler and manages private and shared memory. The SVSM provides
  services to the guest OS which can not be securely provided by the
  hypervisor, like emulating devices with security-sensitive state.
* **Paravisor mode**: This mode is for running guest operating systems which
  have limited or no support for handling CVM specifics. The SVSM is
  responsible for handling VE/VC exceptions on behalf of the guest OS and
  manage private and shared memory. In addition to that the SVSM will still
  emulate security sensitive devices on behalf of the host hypervisor.
* **Service-VM mode**: When running in this mode, the SVSM is the operating
  system of the CVM and does not run alongside another guest OS in the same
  TEE.  The services are provided to other CVMs via a hypervisor-provided
  communication channel.

### Multiple Platform Support

Support for multiple platforms is another major goal of COCONUT-SVSM. Platforms
include multiple hardware platforms like AMD SEV-SNP, Intel TDX and ARM CCA as
well as multiple hypervisor platforms like QEMU/KVM and Hyper-V.

The following sections list the planned or in-progress development items needed
for COCONUT-SVSM to achieve its mission and principles.

### Rust is the Default Programming Language

Unless otherwise noted the whole COCONUT-SVSM code base is written in the Rust
programming language. This includes the COCONUT kernel and all user-space
libraries and binaries.

## Core Code

This sections lists proposed work items on the COCONUT-SVSM core parts.

### Convert to Fallible Allocators

The COCONUT kernel uses the standard Rust allocator interface. This
comes with implicit panics on allocation failures and only supports one
backend allocator. A panic on a memory allocation failure is not acceptable in a
kernel environment so a conversion to a better allocator interface is required.
The interface needs to return errors for allocation failures.

### Getting Rid of Kernel Direct-Map

The COCONUT kernel currently uses a direct map of VMPL0 physical memory. The
direct map is contrary to the isolation goals of COCONUT-SVSM and should be
removed in order to increase security of the overall architecture and achieve
actual isolation.

This is a multi-step approach which requires a rewrite of the page allocator
and the way heap allocation works. Allocation and usage of shared memory will
also fundamentally change.

### Move Stage2 Functionality into IGVM builder/loader

Most of the setup done by the COCONUT stage2 loader can be done at build time
with the IGVM format. Modify the build process and resulting IGVM file to match
this goal and remove functionality from stage2.

### IGVM Memory Map

The COCONUT kernel consumes the system memory map via IGVM parameters, but the
UEFI bios based on EDK2 loads it via QEMU FWCFG. Modify the boot flow so that
COCONUT forwards an updated IGVM memory map to EDK2.

### Dynamic Memory Sizing

With the ability to forward a modified IGVM memory map to the subsequent boot
steps, enhance COCONUT to allocate a variable amount of memory at boot as
needed. The use-case is to allocate data structures whose size depends on the
amount of memory and VCPUs.

### Track Validation State per 4KiB Page

In order to mitigate a various possible double-validation attacks for memory
pages, the COCONUT kernel needs to track the validation state of each 4KiB page
in the system. Implement the data structures and integrate the checks in the
page validation backends.

### Implement Generic Kernel Event Loop

The current kernel event loop in the COCONUT kernel can only handle SVSM
requests. Implement a generic loop which can handle events from multiple
sources and dispatch them to their handlers.

### Re-Work PerCPU Code

The PerCPU code in COCONUT is a constant source of unsafe and unsound behavior.
The best way to fix this is a re-implemnentation which ensures references can
not leak to other CPUs and which enforces Rust's borrowing and memory safety
rules.

A re-implementation also needs to support dynamic allocation/deallocation of
PerCPU memory.

### Use User-Mode Heap in the COCONUT Kernel

Re-work the COCONUT kernel memory allocators to use the heap implementation
from the user-mode support library. This is required to remove the direct map.

### Timer Support

The COCONUT kernel will have to provide timers in the future. Implement support
for timers based on the APIC timer hardware.

### Time Keeping

Related to timers the COCONUT kernel needs a (secure) way to check how much
wall-clock time has elapsed between two events. This needs interfaces on the
kernel and user-mode side.

### Preemptive Multitasking

In order to support new use-cases and prevent COCONUT-SVSM from suspending
guest execution for too long (causing soft-lockups), implement preemptive
multitasking in the COCONUT kernel to better share CPU resources.

### Crypto Library

Having a common crypto library is no pre-requisite to other items in this
document.  Initially other parts of COCONUT-SVSM can use their own cryptography
libraries and be converted to a common implementation once it is ready to use.

The goal is to have a shared common library which is linked into the respective
components. This includes the COCONUT kernel as well as user-mode binaries.

The library provides a stable public interface and supports different backend
implementations. This allows to use third-party crypto libraries (like OpenSSL
or BoringSSL) with a common Rust-based frontend.

## User-Mode Support

This section lists the work items to implement support for running services in
user-mode.

### Heap Allocator

User-mode binaries need dynamic memory allocation. This will be provided by a
heap allocator which supports all necessary allocation sizes and can be used
from non-rust user-mode code as well. This means that the size of the
allocation is not required as an input to a free operation.

### Define a System Call ABI

Make definitions for how system call parameters are communicated between
user-space and the COCONUT kernel. Design all data structures for user-kernel
communication in a way that is usable with other programming languages as well.

### Define SYSCALL batching Mechanism

In a paravisor setup it will become necessary to handle a larger number of
system calls to fulfill requests. Issuing single system calls can become a
performance problem, so a batching mechanism to allow sending multiple system
calls within one request is needed.

### IPC and Event Delivery Framework

User-mode and kernel components in COCONUT-SVSM need communication
interfaces to send and receive data and events. A framework enabling the
communication needs to be designed and implemented in the COCONUT kernel.

### Create Init Task

Implement an user-mode process for the SVSM which is launched as the first
user-mode process by the COCONUT kernel. It is responsible for setting up the
execution environment and launches other user-mode services as specified by a
configuration file provided with the RAM file-system.

### Move Request-Loop to User-Mode

Create a simple user-mode process which executes the request-loop for SVSM
protocol requests in user-mode. Initially most of the actual handling can stay
in kernel-mode, but this process is a starting point to move most of request
parsing and handling to user-mode as well.

### Define VMM Interface

The COCONUT kernel needs to provide a VMM-like interface for user-mode
processes to control the execution of the guest operating system. This
interface should be flexible enough to support the **Enlightened OS Mode** and
**Paravisor Mode** of operation.

This interface will also allow to run deployment specific versions of VM
management tasks in user-mode.

### COCONUT-SVSM as Rust Tier-3/Tier-2 Target

To make it easier to develop new user-mode modules and bring the Rust standard
library to the COCONUT-SVSM ecosystem, support for a COCONUT platform target in
the upstream Rust project required.

### User-mode Security Framework

Define and implement a security framework which allows to limit the
capabilities of user-mode processes to interact with the SVSM kernel. In Linux
terms this would be similar to SELinux.

## Services

### Move vTPM to User-Mode

Move the vTPM emulation code into a user-mode service.

### Provide UEFI Variable Store Service

Implement a service to store UEFI variables in the SVSM.

## Paravisor Support

Besides enlightened guest operating systems COCONUT-SVSM should support
un-enlightened operating systems as well. This requires a lot of new
functionality to offload CVM specific handling from the OS into the SVSM.

### MMIO/IOIO Event Dispatch Framework

A framework is needed to dispatch MMIO and IOIO events to different user-mode
services or kernel-mode components, based on the MMIO address or IOIO
port-range targeted by the access.

### User/Kernel VE/VC Event Handlers 

Implement handlers in user- or kernel-mode for all possible VE/VC events
triggered by the guest OS. The default target is user-mode, only handling
events in kernel mode when there are very good reasons for it (e.g.
performance).

## Device Support

The COCONUT kernel needs to support a small number of devices for use of its
own. Examples are block devices for persistence or devices for communicating
with the host.

## Persistence

One of the main use-cases for the SVSM is to emulate devices containing
security sensitive state in a trusted environment. In order for the security
sensitive state to be persistent across restarts of the CVM instance, a
persistency layer is needed.

### Block Layer

The COCONUT-SVSM will need to support different storage backends for
persistent storage. In order to have a common interface to all supported
hypervisors, a generic block layer is needed which is the front-end to specific
backend implementations. Encryption and integrity protection of the storage
will also be implemented on the block layer.

### File System for Persistent Data

A simple file-system driver is needed to support persistence for multiple
services and device emulations. Design is TBD, but there is likely no need to
support directories.

### Permission Model for File System Data

Design and implement a permission model for data on the file system which
allows to limit which persistent data is accessible by a given user-mode
process.

## X86 Platform Support

### TDX: IGVM Boot

The first step to support the TDX platform in COCONUT-SVSM is to implement boot
support via an IGVM platform file. This needs support in the COCONUT kernel as
well as in the QEMU IGVM loader.

### TDX: Multi-processor Support

Booting multiple CPUs in a TD guest needs some modifications in the COCONUT
kernel as on Intel the TD vCPUs start from a fixed address.

### TDX: Boot support

Implement a platform API backend to boot COCONUT-SVSM in an Intel TD with
partitioning support.

### TDX: Paravisor Support

Implement support for running un-enlightened guest operating systems in an
Intel TD using TDX partitioning. It is fine to implement this alongside generic
paravisor support.

### SEV-SNP: Alternate Injection Support

Support taking notifications for IRQs to lower privilege levels in the COCONUT
kernel and use the *Alternate Injection* feature to inject the IRQs into the
guest OS.

## Observability

### Implement Observability Interface

Specify a protocol to allow to observe the state of COCONUT-SVSM from the guest
OS. This includes information like log-files, memory usage information, and
more.

Implement a handler for the protocol in COCONUT-SVSM and a driver plus tooling
on the guest OS side.

### Bring LogBuffer Code Upstream

The COCONUT kernel needs to put its log messages into a log buffer which is not
printed to the console by default. Anything printed to the serial console is
visible to the untrusted hypervisor and might reveal information to attack the
SVSM.

There is a pending PR to implement a log buffer. Review that PR and bring it
upstream.

## Hypervisor Support

## Securing COCONUT-SVSM Code Base

This section lists a loosely coupled list of work items to improve the security
of the COCONUT-SVSM platform.

### Fixing Unsound Code Patterns

The GitHub issues for the COCONUT-SVSM contains an issue which lists unsound
code patterns. This list needs to be updated, evaluated and the patterns need
to be fixed.

### Improve Fuzzing

The COCONUT-SVSM repository contains a good number of fuzzers already for parts
of the code-base. Build on that and extended the fuzzers over time to cover
more or most code of the COCONUT-SVSM platform.

As part of this effort, identify security-critical interfaces to be fuzzed.

### Adding Stress-Tests

This is related to fuzzing, but targeted at a fully running COCONUT-SVSM
instead of individual parts of the code. Stress tests need to be implemented to
find any kind of issues in the kernel and user-mode code, especially race
conditions, lock inversions, and so on.
