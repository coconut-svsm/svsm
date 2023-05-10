Installing the COCONUT-SVSM
===========================

Installation of the COCONUT-SVSM requires some components that are not
upstream in their respective repositories yet:

* Linux host kernel with SVSM support
* Linux guest kernel with SVSM support
* EDK2 with SVSM support
* A modified QEMU which supports the current SVSM launch protocol
* The SVSM source-code repository

The next sections will guide through the process of installing these
components and running the SVSM. All steps require a Linux environment
on the host.

Preparing the Host
------------------

To run the SVSM a host machine with an AMD EPYC Generation 3 or newer
processor is required. Also make sure that SEV-SNP is enabled in the
BIOS settings.

A patched host kernel which has the SEV-SNP host patches as well as the
SVSM support patches applied is needed on the host machine.

A repository based on the SNP-v8 patch-set with support for unmapped
private memory and SVSM support on-top is available here:
[https://github.com/coconut-svsm/linux](https://github.com/coconut-svsm/linux).
It is based on the code written by AMD to support [linux-svsm](https://github.com/AMDESE/linux-svsm/).

To use it, check out the svsm-host branch:

```
$ git clone https://github.com/coconut-svsm/linux
$ cd linux
$ git checkout svsm-host
```

Build, install and boot a kernel from that branch. For best chances of
success use a kernel configuration provided by the distribution. On
openSUSE (other distributions may vary) the kernel configuration can be
obtained by:

```
$ gunzip -c /proc/config.gz > .config
$ make olddefconfig
```

After the new kernel is booted, the kernel log contains SEV-SNP
initialization messages:

```
$ dmesg | grep SEV
[    4.224504] SEV-SNP: RMP table physical address [0x0000000064000000 - 0x00000000747fffff]
[    8.437424] ccp 0000:42:00.1: SEV firmware update successful
[    9.404744] ccp 0000:42:00.1: SEV API:1.51 build:3
[    9.410251] ccp 0000:42:00.1: SEV-SNP API:1.51 build:3
[   11.340252] kvm_amd: SEV supported: 382 ASIDs
[   11.340253] kvm_amd: SEV-ES and SEV-SNP supported: 127 ASIDs
```

If the kernel log contains messages similar to these, the host machine is ready
to run AMD SEV-SNP guests.

Building QEMU
-------------

Currently the COCONUT-SVSM uses a specific launch protocol which
requires changes to QEMU. So a special QEMU build is needed to run the
code.

First make sure to have all build requirements for QEMU installed. RPM
and DEB based distributions provide ways to install build dependencies
for a given package. On openSUSE the source repositories need to be
enabled and then the packages can be installed by:

```
$ sudo zypper refresh
$ sudo zypper si -d qemu-kvm
```

After the build dependencies are installed, clone the QEMU repository
with the SVSM changes:

```
$ git clone https://github.com/coconut-svsm/qemu
$ cd qemu
$ git checkout svsm
```

Now the right branch is checked out and you can continue with the build.
Feel free to adapt the installation directory to your needs:

```
$ ./configure --prefix=$HOME/bin/qemu-svsm/ --target-list=x86_64-softmmu
$ ninja -C build/
$ make install
```

QEMU is now installed and ready to run an AMD SEV-SNP guest with an
SVSM.

Building the guest firmware
---------------------------

A special OVMF build is required to launch a guest on top of the
COCONUT-SVSM. The changes also build on the EDK2 patches from AMD for
linux-svsm. But these changes were re-based and enhanced to support the
COCONUT-SVSM code base. 

The source code for the special OVMF build is included as a submodule of
the COCONUT-SVSM repository and is built along with the COCONUT-SVSM 
using the provided Makefile so no extra steps are required to build OVMF.

However, the build dependencies for OVMF must be installed prior to building
COCONUT-SVSM. On openSUSE you can do this by:

```
$ sudo zypper si -d qemu-ovmf-x86_64
```

Preparing the guest image
-------------------------

The guest image for the SEV-SNP SVSM guest needs to have a kernel
installed that supports running in a lower-privileged VMPL than VMPL0
and supports the SVSM request protocol. If you already experimented with
the linux-svsm you can re-use the guest image.

Otherwise you need to build a new guest kernel. From within the guest
image, do:

```
$ git clone https://github.com/coconut-svsm/linux
$ cd linux
$ git checkout svsm-guest
```

Build a kernel from that branch and install it in the guest image. For
the guest kernel configuration you can follow the same steps as for the
host kernel. Best results are achieved by re-using the kernel
configuration from the distribution like for the host kernel.

Building the COCONUT-SVSM
-------------------------

Building the SVSM itself requires a recent Rust-nightly compiler and
build environment installed. Please refer to [https://rustup.rs/](https://rustup.rs/)
on how to get this environment installed.

Then checkout the SVSM repository and build the SVSM binary:

```
$ git clone https://github.com/coconut-svsm/svsm
$ git submodule update --init --recursive
$ cd svsm
```

That checks out the SVSM which can be built by

```
$ make
```

to get a debug build of the SVSM or

```
$ make RELEASE=1
```

to build the SVSM with the release target. 


When the build is finished there will be the file ```svsm.bin``` in the
top-directory of the repository. This contains the binary image for the SVSM
module. However, the makefile also builds a firmware volume that contains the
SVSM module embedded alongside the special build of OVMF. This firmware volume is
the file which needs to be passed to QEMU. The firmware volumes for debug and
release can be found in their respective directories:

```
$ cp ovmf/debug/* /path/to/firmware/
$ cp ovmf/release/* /path/to/firmware/
```

The project also contains a number of unit-tests which can be run by

```
$ make test
```

Putting it all together
-----------------------

The guest is launched using the QEMU built in the previous step. It
needs to run as root because it accesses the /dev/sev device, which is
limited to the root user.

There are a couple of parameters required to launch an AMD SEV-SNP
guest:

```
  -cpu EPYC-v4 \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1,kvm-type=protected \
  -object memory-backend-memfd-private,id=ram1,size=8G,share=true \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,svsm=on \
```

This selects the ```EPYC-v4``` CPU type which will pass the CPUID validation
done by the AMD security processor. It also allocates memory
from the ```memory-backend-memfd-private``` backend, which is a requirement to
run SEV-SNP guests. An ```sev-snp-guest``` object needs to be defined to
enable SEV-SNP protection for the guest. The 'svsm=on' parameter makes
QEMU reserve a small amount of guest memory for the SVSM.

Further, the OVMF binaries with embedded SVSM binary need to be passed to
QEMU. This happens via pflash drives where the standard OVMF firmware is
replaced with the version built using the COCONUT-SVSM Makefile:

```
  -drive if=pflash,format=raw,unit=0,file=/path/to/firmware/OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=/path/to/firmware/OVMF_VARS.fd,snapshot=on \
```

With these extensions QEMU will launch an SEV-SNP protected guest with
the COCONUT-SVSM.

A complete QEMU command-line may look like this:

```
$ sudo $HOME/bin/qemu-svsm/bin/qemu-system-x86_64 \
  -enable-kvm \
  -cpu EPYC-v4 \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1,kvm-type=protected \
  -object memory-backend-memfd-private,id=ram1,size=8G,share=true \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,svsm=on \
  -smp 8 \
  -no-reboot \
  -drive if=pflash,format=raw,unit=0,file=/path/to/firmware/OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=/path/to/firmware/OVMF_VARS.fd,snapshot=on \
  -netdev user,id=vmnic -device e1000,netdev=vmnic,romfile= \
  -drive file=/path/to/guest/image.qcow2,if=none,id=disk0,format=qcow2,snapshot=off \
  -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=on \
  -device scsi-hd,drive=disk0,bootindex=0 \
  -vga std \
  -serial stdio
```

If everything works, initialization messages of the SVSM should appear
in the terminal:

```
[Stage2] COCONUT Secure Virtual Machine Service Module (SVSM) Stage 2 Loader
[Stage2] Mapping kernel region 0xffffff8000000000-0xffffff8010000000 to 0x0000008000000000
[Stage2] Order-00: total pages:    11 free pages:     1
[Stage2] Order-01: total pages:     2 free pages:     1
[Stage2] Order-02: total pages:     0 free pages:     0
[Stage2] Order-03: total pages:     1 free pages:     1
[Stage2] Order-04: total pages:     2 free pages:     2
[Stage2] Order-05: total pages:     2 free pages:     2
[Stage2] Total memory: 476KiB free memory: 428KiB
[Stage2]   kernel_physical_start = 0x0000008000000000
[Stage2]   kernel_physical_end   = 0x0000008010000000
[Stage2]   kernel_virtual_base   = 0xffffff8000000000
[Stage2]   cpuid_page            = 0x000000000009f000
[Stage2]   secrets_page          = 0x000000000009e000
[Stage2] Launching SVSM kernel...
[SVSM] COCONUT Secure Virtual Machine Service Module (SVSM)
[SVSM] Order-00: total pages:    22 free pages:     0
[SVSM] Order-01: total pages:     2 free pages:     1
[SVSM] Order-02: total pages:     0 free pages:     0
[SVSM] Order-03: total pages:     1 free pages:     1
[SVSM] Order-04: total pages:     0 free pages:     0
[SVSM] Order-05: total pages:  2042 free pages:  2042
[SVSM] Total memory: 261512KiB free memory: 261416KiB
[SVSM] Boot stack starts        @ 0xffffff800001b000
[SVSM] BSP Runtime stack starts @ 0xffffff0000204000
[SVSM] Guest Memory Regions:
[SVSM]   000000000000000000-000000000080000000
[SVSM]   000000000100000000-000000000270000000
[SVSM] 8 CPU(s) present
...
```

Have a lot of fun!
