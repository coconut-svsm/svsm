#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) Microsoft Corporation
#
# Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
# A script to install verus tools
VERISMO_REV=4f504b7
VERUS_RUST_VERSION=1.91.0
VERUSFMT_REV=0.5.7
PREBUILT_VERUSFMT=""

for arg in "$@"; do
  case "$arg" in
    --prebuilt-verusfmt)
      PREBUILT_VERUSFMT="https://github.com/verus-lang/verusfmt/releases/download/v$VERUSFMT_REV/verusfmt-installer.sh"
      ;;
    esac
done

# Install x86_64-unknown-none target for verus-compatible Rust version
export RUSTUP_TOOLCHAIN=$VERUS_RUST_VERSION
rustup target add x86_64-unknown-none --toolchain $RUSTUP_TOOLCHAIN
# Install the verus toolchain
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV cargo-v
# verus-rustc as a wrapper to call verus with proper rustc flags.
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV verus-rustc
cargo v install-verus

# Install verusfmt
if [ -n $PREBUILT_VERUSFMT ]; then
    if ! verusfmt --version 2>/dev/null | grep -q "$VERUSFMT_REV$"; then
        curl --proto '=https' --tlsv1.2 -LsSf "$PREBUILT_VERUSFMT" | sh
    else
        echo "verusfmt is already at version $VERUSFMT_REV"
    fi
else
  cargo install --git https://github.com/verus-lang/verusfmt  --rev v$VERUSFMT_REV
fi
