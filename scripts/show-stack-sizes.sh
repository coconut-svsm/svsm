#!/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Author: Tom Dohrmann <erbse.13@gmx.de>
# A script to find functions with excessive stack sizes.
# Requires yq-go and llvm-readelf (bundled with llvm) to be installed.

# Forcefully enable a nightly toolchain.
export RUSTUP_TOOLCHAIN=nightly

# Append -Z emit-stack-sizes to the set of rustflags. The RUSTFLAGS environment variable overrides the flags in the config.
RUSTFLAGS=$(yq '.build.rustflags | join(" ")' .cargo/config.toml)
export RUSTFLAGS="$RUSTFLAGS -Z emit-stack-sizes"

# Build the SVSM kernel.
make bin/svsm-kernel.elf

# Determine the path to the built binary.
if [[ -z "${RELEASE}" ]]; then
    TARGET_PATH=debug
else
    TARGET_PATH=release
fi
SVSM_PATH=target/x86_64-unknown-none/${TARGET_PATH}/svsm

# Print stack frame sizes for all functions, sorted from small to large.
llvm-readelf -C --stack-sizes target/x86_64-unknown-none/${TARGET_PATH}/svsm | sort -bn
