# COCONUT Build Recipes Format

This document describes the format of COCONUT build recipes as consumed by the
`xbuild` program. The program takes a build recipe as input and builds all
tooling and component to generate one or more IGVM output files.

IGVM files are hypervisor specific. The COCONUT source repository ships with
ready-to-use recipes for all supported hypervisors. IGVM files for multiple
hypervisors can be built with on recipe.

## General Format

A build recipe is a text file containing a JSON object. The top-level object
has attributes which point to sub-objects describing different parts of the
build process.

The currently recognized attributes are:

* `igvm`: Parameters for creating IGVM files.
* `kernel`: Configuration for compiling the COCONUT kernel and its boot stages.
* `firmware`: Information on how to retrieve the guest firmware to put into the
   IGVM output file (optional).
* `fs`: Specification of the file-system layout for running user-space modules.

The next section describes a common JSON object format for specifying how to
build a single part of COCONUT-SVSM. The format is called COBI and is used for
the `kernel` and `fs` parts of the build recipe.

### COCONUT Build Item (COBI) Object Format

Build recipe files contain a JSON object for each component to be built. All
the objects have a common set of attributes recognized, which are described
below. This object format is used for building the COCONUT kernel parts and the
user-space modules.

#### `type`: The Build Type

This attribute currently has two supported values:

* `cargo`: Build the component with cargo.
* `make`: Run GNU make to build the component.

The default is `cargo`. Some of the other attributes are specific to either
build type.

#### `output_file`: Expected Build Output File

This is the expected output filename of the build run. It is only recognized
for `make` builds and used as the make target.

#### `manifest`: Build Manifest to use for Cargo.

Path to the `Cargo.toml` file to pass as the build manifest when running cargo.
Default is `None`.

#### `features`: Cargo Features to use for Kernel Component

This attribute points to a comma-separated list of cargo features to enable
when building the specified component. Default is empty.

#### `binary`: Whether to Build a Package or Binary

This is a boolean value and defines the way cargo is invoked:

* If `true`, the component is build with the `--bin` parameter to cargo.
* If `false`, the component is build from the cargo workspace with the
  `--package` parameter.

#### `objcopy`: Output Target for Objcopy run

Each binary built using cargo or make will be processed and copied to the
`bin/` directory using `objcopy`. This attribute specifies the output target
used for the processing. Default is `elf64-x86-64`.

#### `path`: User-Space Module Location

This attribute is only recognized for user-space modules. It points to a string
specifying the relative path of the module in the COCONUT file-system image.

## `igvm`: Parameter for IGVM File Creation

The `igvm` attribute points to an object where each attribute describes IGVM
parameters for a supported hypervisor target. The following targets are
currently supported:

* `qemu`: The QEMU/KVM hypervisor.
* `hyper-v`: Microsoft Hyper-V.
* `vanadium`: Google Vanadium hypervisor based on KVM.

Each target description is an object supporting a common set of attributes for
invoking the `igvmbuilder` and `igvmmeasure` tools.

The supported attributes are described below.

### `output`: Output File Name

The name of the output file to generate. The file will be placed in the `bin/`
directory.

### `platforms`: Host Platforms the IGVM File Supports

This attribute takes an array with a list of platforms to support in the output
IGVM file. The supported platforms are:

* `native`: Non-confidential guest environment.
* `snp`: AMD SEV-SNP guest environment.
* `tdp`: Intel TDX guest environment with support for TD-Partitioning.
* `vsm`: Hyper-V Virtual Secure Mode.

### `policy`: Value of the Policy Field on the SEV-SNP Platform

This is a hex value with the `policy` field used when creating an AMD SEV-SNP
virtual machine with the IGVM file (default: `0x30000`).

### `comport`: Serial Port Number to use for the Console

This attribute specifies the number of the serial port COCONUT uses for console
output.

### `measure`: Expected Launch Measurement Calculation

This has only one supported value for now: `print`. The build script will
invoke the `igvmmeasure` tool on the IGVM file to print the expected SEV-SNP
launch measurement for the specified target hypervisor.

### `check-kvm`: Calculate Launch Measurement for KVM-based Hypervisors

This attribute takes a boolean value which must be set to `true` if the target
hypervisor is based on the Linux Kernel Virtual Machine (KVM). It is used to
calculate the correct expected launch measurement for KVM-based hypervisors.
Default value is `false`.

### `measure-native-zeroes`: How to Measure Zero-Pages

This is a boolean flag which defines how zero-pages are treated when
calculating the expected launch measurement. The behavior is:

* If `true`: Use native SEV-SNP zero-page type for measurement.
* If `false`: Measure pages as data-pages containing all zeroes.

The default value is `false`. Whether this setting is needed depends on how the
hypervisor loads the IGVM file.

## `kernel`: Definitions for Building COCONUT Kernel Parts

The `kernel` attribute points to a JSON object whose attributes describe how to
build the individual parts of the COCONUT kernel. The recognized attributes are:

* `tdx-stage1`: Stage1 needed for TD-Partitioning platforms
* `stage2`: The stage2 loader of the COCONUT kernel
* `svsm`: The COCONUT kernel itself.

Each attribute points to a COBI object, describing the individual build
parameters for each component.

## `firmware`: Retrieval Information for Guest Firmware Image

This attribute is optional and points to a JSON object which allows to specify
where the build script finds the guest firmware image to put into the IGVM file.
It supports the following attributes.

### `env`: Environment Variable with Firmware Image Location

This attribute points to an environment variable name from which the path to
the firmware image file is read.

### `file`: Direct File Path of Firmware Image Location

This attribute points directly to the path of the firmware image location. If
present, it takes precedence over `env`.

### `command`: Execute Command before Firmware Retrieval

This optional attribute points to a JSON array describing a command to execute
before the firmware is retrieved either via `env` or `file`. The command can be
used to build a firmware image and place it at the expected location.

## `fs`: File-system Image Build Information

The `fs` attribute is optional and used to describe the build process and
layout of the file-system image to place into the IGVM file.

There is one recognized attribute: `modules`. It points to a JSON object where
each attribute names a module to build and include into the file-system image.

The attribute name is by default treated as a cargo workspace package name and
points to a JSON object in COBI format. The COBI object can override how the
attribute name is treated during build, e.g. it can be treated as a binary
to build with cargo.

The script will build all user-space components and package them into a
file-system image using the `packit` utility. The image file is then added to
the IGVM file.

## Examples

For examples of working build recipe files please have a look into the
`config/` directory of the COCONUT-SVSM source repository. It contains a number
of build recipes to generate IGVM files for all supported hypervisors.
