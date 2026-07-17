#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) Microsoft Corporation
#
# Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
# A script to install verus tools
set -e
trap 'echo "Error at line $LINENO: $BASH_COMMAND"' ERR

# Verus release version and commit hash
VERUS_VERSION=0.2026.07.12.0b42f4c
VERUS_REV=0b42f4cee92a178937608cf55e512371d2fd8cd4
VERUS_RUST_VERSION=1.96.0

# Verusfmt version and commit hash
VERUSFMT_VERSION=v0.7.2
VERUSFMT_REV=610d4ee7fa4d5a8f0132aad70f8df07fd64adc87 # 0.7.2

# Z3 version and commit hash
VERUS_Z3_VERSION=4.12.5
VERUS_Z3_REV=a7b564cafe3b96c8a868388bc4b96b319facea44

VERUS_INSTALL_DIR="$HOME/.cargo/bin"

# Parse arguments
INSTALL_PREBUILT=false
FORCE_INSTALL=false
for arg in "$@"; do
    case "$arg" in
        --use-prebuilt) INSTALL_PREBUILT=true ;;
        --force) FORCE_INSTALL=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# Install x86_64-unknown-none target for verus-compatible Rust version
export RUSTUP_TOOLCHAIN=$VERUS_RUST_VERSION
rustup target add x86_64-unknown-none --toolchain $RUSTUP_TOOLCHAIN

fetch_code() {
    url=$1
    commit=$2
    destdir=$3
    git clone --no-checkout --depth 1 "$url" "$destdir"
    pushd "$destdir" > /dev/null
    git fetch --depth 1 origin "$commit"
    git checkout FETCH_HEAD -b "$commit"
    popd > /dev/null
}

# Install verus toolchain into your ~/.cargo/bin
install_verus_assets() {
    VERUS_ASSETS=(
        "verus"
        "rust_verify"
        "z3"
        "cargo-verus"
        "verus-root"
    )
    local src_dir=$1
    local dst_dir=$2
    for asset in "${VERUS_ASSETS[@]}"; do
        echo "Installing $asset to $dst_dir"
        install "$src_dir/$asset" $dst_dir
    done
}

# Skip building Verus from source if the correct version is already installed
if (verus --version | grep -q "$VERUS_VERSION") &> /dev/null && ! $FORCE_INSTALL; then
    echo "Verus version $VERUS_VERSION already installed, skipping build."
    exit 0
fi

# Prebuilt path: download binaries and exit early
install_prebuilt() {
    ARCH=$(uname -m)
    OS=$(uname -s)
    case "$ARCH" in
        x86_64)        PLATFORM_ARCH="x86" ;;
        aarch64|arm64) PLATFORM_ARCH="arm64" ;;
        *) echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    case "$OS" in
        Linux)  PLATFORM_OS="linux" ;;
        Darwin) PLATFORM_OS="macos" ;;
        *) echo "Error: unsupported OS: $OS" >&2; exit 1 ;;
    esac
    PLATFORM="${PLATFORM_ARCH}-${PLATFORM_OS}"
    ZIPFILE="verus-${VERUS_VERSION}-${PLATFORM}.zip"
    VERUS_RELEASE_URL="https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/${ZIPFILE}"

    # Install verusfmt
    curl --proto '=https' --tlsv1.2 -LsSf https://github.com/verus-lang/verusfmt/releases/download/$VERUSFMT_VERSION/verusfmt-installer.sh | sh

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    curl --proto '=https' --tlsv1.2 -LsSf "$VERUS_RELEASE_URL" -o "$TMPDIR/$ZIPFILE"
    unzip -q "$TMPDIR/$ZIPFILE" -d "$TMPDIR"
    install_verus_assets "$TMPDIR/verus-$PLATFORM" "$VERUS_INSTALL_DIR"
}

if $INSTALL_PREBUILT; then
    install_prebuilt
    exit 0
fi

# Install verusfmt
cargo install --git https://github.com/verus-lang/verusfmt  --rev $VERUSFMT_REV

# Create a temporary directory
TMPDIR=$(mktemp -d)
VERUS_DIR=$TMPDIR/verus
trap 'rm -rf "$TMPDIR"' EXIT

# Fetch Verus source code
fetch_code https://github.com/verus-lang/verus.git "$VERUS_REV" "$VERUS_DIR"

# Build and install Z3 from source if not exists or version is wrong
if ! (z3 --version | grep -q "$VERUS_Z3_VERSION") &> /dev/null || $FORCE_INSTALL; then
    fetch_code https://github.com/Z3Prover/z3 "$VERUS_Z3_REV" "$TMPDIR/z3"
    pushd "$TMPDIR/z3" > /dev/null
    python3 scripts/mk_make.py
    pushd build && make -j$(nproc)
    cp z3 $VERUS_DIR/source
    popd > /dev/null
    popd > /dev/null
else
    echo "Z3 found and version matches $VERUS_Z3_VERSION, skipping build."
    cp $(which z3) $VERUS_DIR/source
fi

# Build and install Verus from source
source $VERUS_DIR/tools/activate
pushd $VERUS_DIR/source
rustup component add rust-src rustc-dev llvm-tools-preview --toolchain $RUSTUP_TOOLCHAIN
vargo build --release --vstd-no-verify
popd > /dev/null
install_verus_assets "$VERUS_DIR/source/target-verus/release" "$VERUS_INSTALL_DIR"
rm -r $TMPDIR