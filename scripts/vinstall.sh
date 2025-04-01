#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) Microsoft Corporation
#
# Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
# A script to install verus tools

VERISMO_REV=a120c45
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV cargo-v
builtin=`cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "builtin_macros") | .targets[].src_path'`
verus=`dirname $builtin`/../../../source/target-verus/release/verus
if [ -f ${verus} ]; then
    echo "verus (${verus}) is already built"
else
    # build the verus using the source code from builtin/vstd defined in
    # Cargo.toml so that the verus lib and tool are compatible.
    cargo v prepare-verus
fi

# verus-rustc as a wrapper to call verus with proper rustc flags.
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV verus-rustc

# verus formatter
cargo install --git https://github.com/verus-lang/verusfmt --rev v0.5.4
