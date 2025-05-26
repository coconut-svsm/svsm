[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8914/badge)](https://www.bestpractices.dev/projects/8914)

COCONUT Secure VM Service Module
================================

This is the source code repository for the COCONUT Secure VM Service
Module (SVSM), a software which aims to provide secure services and
device emulations to guest operating systems in confidential virtual
machines (CVMs). It requires AMD Secure Encrypted Virtualization with
Secure Nested Paging (AMD SEV-SNP), especially the VM Privilege Level
(VMPL) feature.

The COCONUT-SVSM is distributed under the MIT license, which is included in the
[LICENSE-MIT](LICENSE-MIT) file.

The project builds on support code written for the [linux-svsm](https://github.com/AMDESE/linux-svsm),
a software written and published by AMD. This includes the necessary
hypervisor changes for KVM host, guest, and for the EDK2 firmware.

Installation
------------

Detailed installation instructions are in the [INSTALL.md](Documentation/docs/installation/INSTALL.md)
file. It walks through the process of building all the necessary parts
to get a virtual machine powered by the COCONUT-SVSM up and running.

Documentation
-------------

Information about COCONUT-SVSM can be found on at the
[COCONUT-SVSM documentation site](https://coconut-svsm.github.io/svsm).

Community
---------

Development discussions happen on the project mailing list:
- address: coconut-svsm@lists.linux.dev
- archive: https://lore.kernel.org/coconut-svsm/
- subscription/unsubscription: https://subspace.kernel.org/lists.linux.dev.html

Regular development calls are scheduled via the mailing list.

Reporting Bugs
--------------

Any issues, bugs (except embargoed security issues) or feature requests
for the SVSM project can be reported via [https://github.com/coconut-svsm/svsm/issues](https://github.com/coconut-svsm/svsm/issues).

For security critical bugs please send an email describing the problem
and the planned CRD (if known) to
[security@coconut-svsm.dev](mailto:security@coconut-svsm.dev).

Contributing
------------

Contributing to the project is as easy as sending a pull-request via
GitHub. For detailed instructions on patch formatting and contribution
guidelines please have a look at [CONTRIBUTING.md](Documentation/docs/developer/CONTRIBUTING.md).
For documentation guidelines consult [RUSTDOC-GUIDELINES.md](Documentation/docs/developer/RUSTDOC-GUIDELINES.md)
and [DOC-GUIDELINES.md](Documentation/docs/developer/DOC-GUIDELINES.md).

The [development plan document](Documentation/docs/developer/DEVELOPMENT-PLAN.md)
lists planned and in-progress work items.

Documentation
-------------

Coconut-SVSM components are documented using rustdoc, a tool that produces
a user-friendly, browsable website explaining the code's contents. To
generate and open the documentation, simply execute the following command:

```
$ make doc
```

Acknowledgments
---------------

The COCONUT-SVSM project would not have been possible without the close
relationship to AMD. AMD provided the Linux kernel and OVMF
modifications to complete the SVSM host and guest stack. Many thanks for the
work and our continuous cooperation!
