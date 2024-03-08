# igvm

[![crates.io](https://img.shields.io/crates/d/igvm?label=crates.io%2Figvm)](https://crates.io/crates/igvm)
[![docs.rs](https://img.shields.io/docsrs/igvm?label=docs.rs%2Figvm)](https://docs.rs/igvm/)
[![crates.io](https://img.shields.io/crates/d/igvm_defs?label=crates.io%2Figvm_defs)](https://crates.io/crates/igvm_defs)
[![docs.rs](https://img.shields.io/docsrs/igvm_defs?label=docs.rs%2Figvm_defs)](https://docs.rs/igvm_defs/)

This project is the home of the Independent Guest Virtual Machine (IGVM) file
format. The format specification can be found in the
[`igvm_defs`](https://crates.io/crates/igvm_defs) crate, with a Rust
implementation of the binary format in the
[`igvm`](https://crates.io/crates/igvm) crate.

The IGVM file format is designed to encapsulate all information required to
launch a virtual machine on any given virtualization stack, with support for
different isolation technologies such as AMD SEV-SNP and Intel TDX.

At a conceptual level, this file format is a set of commands created by the
tool that generated the file, used by the loader to construct the initial
guest state. The file format also contains measurement information that the
underlying platform will use to confirm that the file was loaded correctly
and signed by the appropriate authorities.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
