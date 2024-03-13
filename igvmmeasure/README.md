# igvmmeasure
A tool to calculate the launch measurement for the directives in an IGVM file.

When starting a guest configured using an IGVM file, the directives in the IGVM
are use to populate initial guest memory and describe the initial guest state.
This configuration is measured by the isolation technology, such as SEV-SNP or
TDX and results in a launch digest that can be remotely verified using an
attestation report.

In order to ensure the integrity of a build that is packed in IGVM, it is
necessary to be able to pre-calculate the measurement of the file to obtain the
expected launch digest. This can then be compared with the actual launch
measurement in the attestation report to ensure the initial guest state is as
expected.

Given an IGVM file, igvmmeasure parses the directives in the file and calculates
the launch digest and outputs it as a hexadecimal string.

## Usage
`igvmmeasure [OPTIONS] <IGVM_FILE>`

### Arguments:
```
  <IGVM_FILE>
          The filename of the IGVM file to measure
```

### Options:
```
  -v, --verbose    Print verbose output
  -b, --bare       Bare output only, consisting of just the digest as a hex string
  -p, --platform <PLATFORM>
          Platform to calculate the launch measurement for
          [default: sev-snp]
          Possible values:
          - sev-snp: Calculate the launch measurement for SEV-SNP
  -h, --help       Print help
```
