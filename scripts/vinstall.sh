#!/bin/bash
VERISMO_REV=7c9c445
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV cargo-v
builtin=`cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "builtin_macros") | .targets[].src_path'`
verus=`dirname $builtin`/../../../source/target-verus/release/verus
if [ -f ${verus} ]; then
    echo "verus (${verus}) is already built"
else
    cargo v prepare-verus 
fi
cargo install --git https://github.com/microsoft/verismo/ --rev $VERISMO_REV verus-rustc
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/verus-lang/verusfmt/releases/download/v0.4.3/verusfmt-installer.sh | sh
sudo apt-get install build-essential ninja-build libclang-dev
