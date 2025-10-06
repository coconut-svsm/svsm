#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Joerg Roedel <jroedel@suse.de>

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

test_io(){
    PIPE_IN=$1
    PIPE_OUT=$2
    while read -r -n 1 -u 3 BYTE; do
        TEST=$(printf '%s' "$BYTE" | xxd -p)
        case $TEST in
            # 0x00: NOP
            "00")
                ;;
            # 0x01: return SEV-SNP pre-calculated launch measurement (48 bytes)
            "01")
                $SCRIPT_DIR/../bin/igvmmeasure \
                    $SCRIPT_DIR/../bin/coconut-test-qemu.igvm measure -b \
                    | xxd -r -p > $PIPE_IN
                ;;
            # 0x02 Virtio-blk test: send md5 sum of svsm state image to SVSM.
            "02")
              sha256sum "$TEST_DIR/svsm_state.raw" | cut -f 1 -d ' ' | xxd -p -r > "$PIPE_IN"
              ;;
            "03")
              echo -n "hello_world" | nc -l --vsock 12345 &
              sleep 1
              echo -n "0" > $PIPE_IN
              ;;
            "")
                # skip EOF
                ;;
            *)
                echo "Unsupported test: $TEST"
                ;;
        esac
    done 3< "$PIPE_OUT"
}

TEST_DIR=$(mktemp -d -q)
mkfifo $TEST_DIR/pipe.in
mkfifo $TEST_DIR/pipe.out
# Create a raw disk image (512kB in size) for virtio-blk tests containing random data
dd if=/dev/urandom of="$TEST_DIR/svsm_state.raw" bs=512 count=1024

test_io $TEST_DIR/pipe.in $TEST_DIR/pipe.out &
TEST_IO_PID=$!

$SCRIPT_DIR/launch_guest.sh --igvm $SCRIPT_DIR/../bin/coconut-test-qemu.igvm \
    --state "$TEST_DIR/svsm_state.raw" \
    --vsock 3 \
    --unit-tests $TEST_DIR/pipe || true

kill $TEST_IO_PID 2> /dev/null || true
rm -rf $TEST_DIR
