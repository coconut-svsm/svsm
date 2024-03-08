# PackIt

A simple library and CLI utility to pack filesystems into single blobs. It is a rework of the [original tooling written by Jörg Rödel](https://github.com/joergroedel/packit).

## Feature flags ##

Without any feature flags, the crate can only decode archive blobs - this might be sufficient for embedded systems or early boot software which might not have an allocator or a standard library.

On top of that, several incremental feature flags can be enabled:

* `alloc`: builds the library with `alloc` support, which enables the use of the `PackItArchive` struct for easier archive manipulation.
* `std`: links the library to the Rust std library, which enables the use of the `PackItArchiveEncoder` struct and allows encoding an archive into any type that implements [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html).
* `cli`: builds a CLI utility for archive packing, unpacking and listing. Install this tool with `cargo install --path $(repo) -F cli`.

Full details of the library API are provided via `cargo doc`.

## CLI tool ##

The command line tool is very simple to use. It has 3 subcommands: `pack` packs a directory into a PackIt archive; `unpack` extracts a PackIt archive into a local directory; `list` simply lists the files in an archive. Full command help can be displayed via `packit -h` and `packit <subcommand> -h`.
