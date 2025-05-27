CONTRIBUTING
============

Submissions to the project are accepted via pull-requests on
GitHub against this repository: [https://github.com/coconut-svsm/svsm](https://github.com/coconut-svsm/svsm)

Patches may also be sent to the development mailing list
(coconut-svsm@lists.linux.dev) for review.

Patch Format
------------

Each patch must start with a subject line that contains the component
the patch changes and a short description of the change, separated by a
colon. The text after the colon needs to start with a capital letter.
For example:

```
SVSM/locking: Annotate spin-loops with core::hint::spin_loop()
```

A detailed description is also required for every patch. The description
should state what the change is about and optionally why the change was
necessary.

At the end of the patch, it needs to be signed off with a
```Signed-off-by``` tag as created by ```git commit -s```. If a patch
was written by more than one person, then additional developers can be
added via a ```Co-developed-by``` tag.

The user and email stated in the  ```Signed-off-by``` tag must be equal
to the ```Author``` field of the patch. By adding ```Signed-off-by```
the submitter attests that the contribution fulfills the requirements of
the [Developer Certificate of Origin](https://developercertificate.org/).

Coding Style
------------

Submitted changes must be checked with ```rustfmt``` before submitting
and submitted code must not introduce new warnings in the build process.

Make sure to format the code according to Rust edition 2021. There is a
git-hook in the scripts directory which checks any changes with rustfmt
before allowing them to be committed. It can be installed by running

```
./scripts/install-hooks.sh
```

from the projects root directory.

For detailed instructions on documentation guidelines please have a look at
[RUSTDOC-GUIDELINES.md](RUSTDOC-GUIDELINES.md).

Fuzzing
-------

The SVSM project includes a number of fuzzing targets to test parts of the
code-base. For details on how to run the fuzzers and extend the fuzzing
functionality, please have a look at [FUZZING.md](FUZZING.md).
