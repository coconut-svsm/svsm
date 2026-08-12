# CONTRIBUTING

Submissions to the project are accepted via pull-requests on
GitHub against this repository: [https://github.com/coconut-svsm/svsm](https://github.com/coconut-svsm/svsm)

Patches may also be sent to the development mailing list
(coconut-svsm@lists.linux.dev) for review.

## Commit Format

Each commit description must start with a subject line that contains the
component changed and a one-line description of the change, separated by a
colon. For example:

```
SVSM/locking: Annotate spin-loops with core::hint::spin_loop()
```

A detailed description is also required for every commit. The description
should state what the change is about and optionally why the change was
necessary.

At the end of the commit, it needs to be signed off with a
`Signed-off-by` tag as created by `git commit -s`. If a commit
was written by more than one person, then additional developers can be
added via a `Co-developed-by` tag.

The user and email stated in the  `Signed-off-by` tag must be equal
to the `Author` field of the patch. By adding `Signed-off-by`
the submitter attests that the contribution fulfills the requirements of
the [Developer Certificate of Origin](https://developercertificate.org/).

## Coding Style

Submitted changes must be checked with `cargo fmt --check` before submitting
and submitted code must not introduce new warnings in the build process. With
`cargo fmt` (without `--check`) cargo will automatically update the formatting
of the changes to match the requirements.

Make sure to format the code according to Rust edition 2024. There is a
git-hook in the scripts directory which checks any changes with `rustfmt`
before allowing them to be committed. It can be installed by running

```
./scripts/install-hooks.sh
```

from the projects root directory.

For detailed instructions on documentation guidelines please have a look at
[RUSTDOC-GUIDELINES.md](RUSTDOC-GUIDELINES.md).

## Linting

In addition to `rustfmt`, it is required to run `clippy` before submitting
changes to catch common mistakes and improve code quality.  The Makefile
provides a `clippy` target that runs it with the appropriate target and
options for each crate:

```
make clippy
```

To check all feature combinations using `cargo-hack`:

```
make clippy CARGO_HACK=1
```

This requires `cargo-hack` to be installed:

```
cargo install cargo-hack
```

## Fuzzing

The SVSM project includes a number of fuzzing targets to test parts of the
code-base. For details on how to run the fuzzers and extend the fuzzing
functionality, please have a look at [FUZZING.md](FUZZING.md).

For the impatient a script is provided to run all available fuzzers in the background for a configurable amount of time:

```
./scripts/run-fuzzers.sh
```

This will run all fuzzers for the default of 10 minutes. The runtime can be
configured with the `-r` option, which takes a number of seconds to run each
fuzzing target. To run all fuzzers for an hour, do:

```
./scripts/run-fuzzers.sh -r 3600
```
