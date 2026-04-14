#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) Microsoft Corporation
#
# Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
# A script to install verus tools
VERISMO_REV=1840262abbcf32f0bd5e622e47fb18d7dfaca795
VERUS_RUST_VERSION=1.94.0
VERUSFMT_REV=beff2fa686d856d5e60df368fd027d94ead11ac5 # v0.5.7

# Install x86_64-unknown-none target for verus-compatible Rust version
export RUSTUP_TOOLCHAIN=$VERUS_RUST_VERSION
rustup target add x86_64-unknown-none --toolchain $RUSTUP_TOOLCHAIN
# Install the verus toolchain
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV cargo-v
cargo v install-verus
cargo install --git https://github.com/verus-lang/verusfmt  --rev $VERUSFMT_REV
