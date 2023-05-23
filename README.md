COCONUT Secure VM Service Module
================================

This is the source code repository for the COCONUT Secure VM Service
Module (SVSM), a software which aims to provide secure services and
device emulations to guest operating systems in confidential virtual
machines (CVMs). It requires AMD Secure Encrypted Virtualization with
Secure Nested Paging (AMD SEV-SNP), especially the VM Privilege Level
(VMPL) feature.

The COCONUT-SVSM is dual-licensed under the MIT and Apache-2.0 licenses.
The licenses are included in the [LICENSE.MIT](LICENSE.MIT) and
[LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt) files.

The project builds on support code written for the [linux-svsm](https://github.com/AMDESE/linux-svsm),
a software written and published by AMD. This includes the necessary
hypervisor changes for KVM host, guest, and for the EDK2 firmware.

Some of the key parts already implemented are:

* SVSM core protocol support
* Boots SMP Linux guests
* Buddy and slab-based memory allocator
* PerCPU page-tables with dedicated address space areas for shared and
  PerCPU mappings
* Backtraces
* Exception fixups
* Multi-stage launch process so it can run from any guest physical
  address

In the future the COCONUT-SVSM will gain support to run modules at ring
3. These modules can extend the SVSM base functionality and implement
advanced features like TPM emulation and live migration.

Installation
------------

Detailed installation instructions are in the [INSTALL.md](INSTALL.md)
file. It walks through the process of building all the necessary parts
to get a virtual machine powered by the COCONUT-SVSM up and running.

Reporting Bugs
--------------

Any issues, bugs or feature requests for the SVSM project can be reported via
[https://github.com/coconut-svsm/svsm/issues](https://github.com/coconut-svsm/svsm/issues).

Contributing
------------

Contributing to the project is as easy as sending a pull-request via
GitHub. For detailed instructions on patch formatting and contribution
guidelines please have a look at [CONTRIBUTING.md](CONTRIBUTING.md).

TODO List
---------

The project is far from being ready. Here is an list of next steps that
are planned for the COCONUT-SVSM. The items are not sorted in
any way:

* Improve documentation
* Support for modules running in ring 3
  * vTPM emulation
* Attestation support
* Persistency layer (needed for TPM and others)
* Live migration

Acknowledgments
---------------

The COCONUT-SVSM project would not have been possible without the close
relationship to AMD. AMD provided the Linux kernel and OVMF
modifications to complete the SVSM host and guest stack. Many thanks for the
work and our continuous cooperation!
