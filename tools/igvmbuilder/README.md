# IGVMBuilder
A tool to build IGVM files that describe the configuration of a guest that
includes coconut SVSM along with firmware such as OVMF.

The IGVM format allows a guest to be configured regardless of the virtualization
stack it will be running on. An IGVM file includes an ordered list of directives
that define the memory layout, initial CPU state and location and content of
binary images including firmware and SVSM. This allows the configuration of the
guest to be fixed at build time which, when working with trusted execution
environments such as AMD SEV-SNP or Intel TDX, can allow for pre-calculation of
a launch measurement that can be verified by hardware.

The IGVMBuilder currently creates IGVM files that are suitable for launching
SEV-SNP guests on QEMU/KVM and Hyper-V including coconut SVSM with or without
firmware - OVMF on QEMU and IGVM-based firmware on Hyper-V.


## Usage
`igvmbuilder [OPTIONS] --stage2 <STAGE2> --kernel <KERNEL> --output <OUTPUT> <HYPERVISOR>`

### Arguments:
```
  <HYPERVISOR>
          Hypervisor to generate IGVM file for

          Possible values:
          - qemu:    Build an IGVM file compatible with QEMU
          - hyper-v: Build an IGVM file compatible with Hyper-V
```

### Options:
```
  -s, --stage2 <STAGE2>
          Stage 2 binary file

  -k, --kernel <KERNEL>
          Kernel elf file

      --filesystem <FILESYSTEM>
          Optional filesystem image

  -f, --firmware <FIRMWARE>
          Optional firmware file, e.g. OVMF.fd

  -o, --output <OUTPUT>
          Output filename for the generated IGVM file

  -c, --comport <COMPORT>
          COM port to use for the SVSM console. Valid values are 1-4
          [default: 1]

  -v, --verbose
          Print verbose output

  --sort
          Sort the IGVM Page directives by GPA from lowest to highest

--policy <POLICY>
          A hex value containing the guest policy to apply. For example: 0x30000

  -h, --help
          Print help (see a summary with '-h')
```
