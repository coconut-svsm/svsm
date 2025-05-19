Installing the COCONUT-SVSM
===========================

Installation of the COCONUT-SVSM requires some components that are not
upstream in their respective repositories yet:

* Linux host kernel with SVSM support
* Linux guest kernel with SVSM support
* EDK2 with SVSM support
* A modified QEMU which supports launching guests configured using IGVM
* The SVSM source-code repository

The next sections will guide through the process of installing these
components and running the SVSM. All steps require a Linux environment
on the host.

Preparing the Host
------------------

To run the SVSM a host machine with an AMD EPYC Generation 3 or newer
processor is required. Also make sure that SEV-SNP is enabled in the
BIOS settings.

A patched kernel which has the SEV-SNP host patches as well as the SVSM
support patches applied is needed on the host machine.

A repository based on the SNP-host patches with support for
`guest-memfd` and SVSM support on-top is available here:
[https://github.com/coconut-svsm/linux](https://github.com/coconut-svsm/linux).
It is based on kernel 6.5 and code written by AMD to support [linux-svsm](https://github.com/AMDESE/linux-svsm/).

To use it, check out the svsm branch:

```
$ git clone https://github.com/coconut-svsm/linux
$ cd linux
$ git checkout svsm
```

Build, install and boot a kernel from that branch. For best chances of
success use a kernel configuration provided by the distribution. Make
sure the configuration includes support for AMD Secure Processor which is
a requirement for SEV support (`CONFIG_KVM_AMD_SEV`). On openSUSE (other
distributions may vary) the kernel configuration can be obtained by:

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

COCONUT-SVSM is packaged during the build into a file conforming to the
[Independent Guest Virtual Machine (IGVM)
format](https://docs.rs/igvm_defs/0.1.3/igvm_defs/index.html). Current versions
of QEMU do not support launching guests using IGVM, but a branch is available
that includes this capability. This will need to be built in order to be able to
launch COCONUT-SVSM.

First make sure to have all build requirements for QEMU installed. RPM
and DEB based distributions provide ways to install build dependencies
for a given package. On openSUSE the source repositories need to be
enabled and then the packages can be installed by:

```
$ sudo zypper refresh
$ sudo zypper si -d qemu-kvm
```

Support for IGVM within QEMU depends on the IGVM library. This will need to be
built and installed prior to building QEMU.

```
git clone https://github.com/microsoft/igvm
cd igvm
make -f igvm_c/Makefile
sudo make -f igvm_c/Makefile install
```

After the build dependencies are installed, clone the QEMU repository
and switch to the branch that supports IGVM:

```
$ git clone https://github.com/coconut-svsm/qemu
$ cd qemu
$ git checkout svsm-igvm
```

Now the right branch is checked out and you can continue with the build.
Feel free to adapt the installation directory to your needs:

```
$ ./configure --prefix=$HOME/bin/qemu-svsm/ --target-list=x86_64-softmmu --enable-igvm
$ ninja -C build/
$ make install
```

QEMU is now installed and ready to run an AMD SEV-SNP guest with an
SVSM embedded in an IGVM file.

Building the guest firmware
---------------------------

A special OVMF build is required to launch a guest on top of the
COCONUT-SVSM. The changes also build on the EDK2 patches from AMD for
linux-svsm. But these changes were re-based and enhanced to support the
COCONUT-SVSM code base. To build the OVMF binary for the guest, checkout
this repository:

```
$ git clone https://github.com/coconut-svsm/edk2.git
$ cd edk2/
$ git checkout svsm
$ git submodule init
$ git submodule update
```

Also make sure to have the build dependencies for OVMF installed. On
openSUSE you can do this by:

```
$ sudo zypper si -d qemu-ovmf-x86_64
```

Then go back to the EDK2 source directory and follow the steps below to
build the firmware. `-DTPM2_ENABLE` is required only if you want to use
the SVSM vTPM.

```
$ export PYTHON3_ENABLE=TRUE
$ export PYTHON_COMMAND=python3
$ make -j16 -C BaseTools/
$ source ./edksetup.sh --reconfig
$ build -a X64 -b DEBUG -t GCC5 -D DEBUG_ON_SERIAL_PORT -D DEBUG_VERBOSE -DTPM2_ENABLE -p OvmfPkg/OvmfPkgX64.dsc
```

This will build the OVMF binary that will be packaged into the IGVM file to use
with QEMU.
You can copy the firmware file to a known location after the build is complete:

```
$ cp Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd /path/to/firmware/
```

Preparing the guest image
-------------------------

The guest image for the SEV-SNP SVSM guest needs to have a kernel
installed that supports the SVSM request protocol and running in a
lower-privileged VMPL than VMPL0. If you already experimented with the
linux-svsm you can re-use the guest image.

Otherwise you need to build a new guest kernel. From within the guest
image, do:

```
$ git clone https://github.com/coconut-svsm/linux
$ cd linux
$ git checkout svsm
```

Build a kernel from that branch and install it in the guest image. For
the guest kernel configuration you can follow the same steps as for the
host kernel. Best results are achieved by re-using the kernel
configuration from the distribution like for the host kernel.

The `CONFIG_TCG_PLATFORM` is required in the guest kernel if you want to
use the SVSM vTPM.

Building the COCONUT-SVSM
-------------------------

Building the SVSM itself requires:
- a recent Rust compiler and build environment installed. Please refer to
  [https://rustup.rs/](https://rustup.rs/) on how to get this environment installed.
- `x86_64-unknown-none` target toolchain installed (`rustup target add x86_64-unknown-none`)
- `binutils` >= 2.39

You may also need to install the TPM 2.0 Reference Implementation build
dependencies. On OpenSUSE you can do this by:

```
$ sudo zypper in system-user-mail make gcc curl patterns-devel-base-devel_basis \
      glibc-devel-static git libclang13 autoconf autoconf-archive pkg-config \
      automake perl
```

Then checkout the SVSM repository and build the SVSM binary:

```
$ git clone https://github.com/coconut-svsm/svsm
$ cd svsm
$ git submodule update --init
```

That checks out the SVSM which can be built by

```
$ FW_FILE=/path/to/firmware/OVMF.fd cargo xbuild configs/qemu-target.json
```

to get a debug build of the SVSM, or

```
$ FW_FILE=/path/to/firmware/OVMF.fd cargo xbuild --release configs/qemu-target.json
```

to build the SVSM with the release target. When the build is finished
there is the ```svsm.bin``` file in the `bin` directory at the top level of the
repository. This is the file which needs to be passed to QEMU.

The project also contains a number of unit-tests which can be run by

```
$ make test
```

Unit tests can be run inside the SVSM by

```
$ QEMU=/path/to/qemu make test-in-svsm
```

Note: to compile the test kernel used for unit tests, we use the nightly
toolchain, so if the test kernel build fails, try installing the
`x86_64-unknown-none` target for the nightly toolchain via your distro or
using rustup:

```
$ rustup +nightly target add x86_64-unknown-none
```

Different (non-QEMU) hypervisors may provide the ACPI tables and ACPI RSDP at
different paths. If this is the case, they can be provided as environment
variables, e.g.
```
$ ACPI_RSDP_PATH=path/to/acpi/rsdp ACPI_TABLES_PATH=path/to/acpi/tables FW_FILE=/path/to/firmware/OVMF.fd make
```
This should only be necessary if using an alternate hypervisor and if SVSM panics
with an error such as `Failed to load ACPI tables: FwCfg(FileNotFound)`. The default
values are "etc/acpi/rsdp" and "etc/acpi/tables", respectively.

Putting it all together
-----------------------

The guest is launched using the QEMU built in the previous step. It
needs to run as root because it accesses the /dev/sev device, which is
limited to the root user.

There are a couple of parameters required to launch an AMD SEV-SNP
guest:

```
  -cpu EPYC-v4 \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1,igvm-cfg=igvm0 \
  -object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false,reserve=false \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
  -object igvm-cfg,id=igvm0,file=/path/to/coconut-qemu.igvm
```

This selects the ```EPYC-v4``` CPU type which will pass the CPUID validation
done by the AMD security processor. It also allocates memory from the
```memory-backend-memfd-private``` backend, which is a requirement to run
SEV-SNP guests. An ```sev-snp-guest``` object needs to be defined to enable
SEV-SNP protection for the guest. The `igvm-file` parameter informs QEMU to load
and configure the guest using directives in the specified IGVM file, which
contains both the COCONUT-SVSM and OVMF binary images.

With these extensions QEMU will launch an SEV-SNP protected guest with
the COCONUT-SVSM.

A complete QEMU command-line may look like this:

```
$ export IGVM=/path/to/coconut-qemu.igvm
$ sudo $HOME/bin/qemu-svsm/bin/qemu-system-x86_64 \
  -enable-kvm \
  -cpu EPYC-v4 \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1,igvm-cfg=igvm0 \
  -object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false,reserve=false \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
  -object igvm-cfg,id=igvm0,file=$IGVM \
  -smp 8 \
  -no-reboot \
  -netdev user,id=vmnic -device e1000,netdev=vmnic,romfile= \
  -drive file=/path/to/guest/image.qcow2,if=none,id=disk0,format=qcow2,snapshot=off \
  -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=on \
  -device scsi-hd,drive=disk0,bootindex=0 \
  -vga std \
  -serial stdio \
  -serial pty
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

Launch Script
-------------

A script is provided in `scripts/launch_guest.sh` that makes it easy to launch a
guest that supports SEV-SNP with COCONUT-SVSM. If the QEMU built in the previous
step is installed and in your PATH then you can start the guest by running the
script from the root of the repository:

```
scripts/launch_guest.sh
```

The script makes use of the `cbit` utility to determine the correct value for
the `cbitpos` QEMU parameter. This needs to be built with the following command:

```
make utils/cbit
```

The path to QEMU can also be specified either by setting the `QEMU` variable, or
by passing the path as a parameter:

```
QEMU=/path/to/qemu-system-x86_64 scripts/launch_guest.sh

scripts/launch_guest.sh --qemu /path/to/qemu-system-x86_64
```

The script supports a number of other options described in the table below

| Command-line     | Variable | Default               | Description                                                                  |
| ---------------- | -------- | --------------------- | ---------------------------------------------------------------------------- |
| `--qemu [path]`  | QEMU     | qemu-system-x86_64    | Path to QEMU binary to use.                                                  |
| `--igvm [path]`  | IGVM     | bin/coconut-qemu.igvm | Path to the IGVM binary to launch.                                           |
| `--image [path]` | IMAGE    | [None]                | The QEMU disk image to use. If unset then no disk is provided on the guest.  |
| `--debugserial`  | N/A      | not set               | Define a second serial port that can be used with the COCONUT-SVSM GDB stub. |

Debugging using GDB
-------------------

The SVSM can be built to incorporate a GDB stub that can be used to provide full
source-level debugging of the SVSM kernel code. To enable the GDB stub pass
```FEATURES=enable-gdb``` to the ```make``` comannd line:

```
$ FW_FILE=/path/to/firmware/OVMF.fd make FEATURES=enable-gdb
```

The GDB stub remains dormant until a CPU exception occurs, either through a
kernel panic or via a debug breakpoint, at which time the GDB stub will await a
serial port connection and display this message in the console:

```
[SVSM] ***********************************
[SVSM] * Waiting for connection from GDB *
[SVSM] ***********************************
```

The GDB stub uses a hardware serial port at IO port 0x2f8, which is the second
simulated serial port in the QEMU configuration. Using the example configuration
above, the serial port is configured using:

```
  - serial pty
```

QEMU will create a virtual serial port on the host at `/dev/pts/[n]` where `[n]`
is the device index. This index will be reported by QEMU in the console when the
virtual machine is started. You can then connect GDB to the waiting SVSM using
the command, replacing `[n]` with the correct device index:

```
$ sudo gdb --ex "target extended-remote /dev/pts/[n]`
```

If you have the source code available on the host system then you can add the
debug symbols and use source-level debugging:

```
(gdb) symbol-file target/x86_64-unknown-none/debug/svsm
```

Note that some GDB features are not available for debugging the SVSM kernel due
to limited debug capabilities inside an AMD SEV-SNP confidential container. Some
of these limitations may be addressed in future updates.

* Hardware breakpoints and watchpoints are not yet supported.
* Interrupting a running kernel with Ctrl-C is not possible. You must insert a
  forced breakpoint in the code to enter the debugger before stepping through
  target code.
* Debugging is currently limited to the SVSM kernel itself. OVMF and the guest
  OS cannot be debugged using the SVSM GDB stub.



Have a lot of fun!
