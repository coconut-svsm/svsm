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
    while true; do
        TEST=$(head -c 1 $PIPE_OUT | xxd -p)
        case $TEST in
            # 0x00: NOP
            "00")
                ;;
            "")
                # skip EOF
                ;;
            *)
                echo "Unsupported test: $TEST"
                ;;
        esac
    done
}

PIPES_DIR=$(mktemp -d -q)
mkfifo $PIPES_DIR/pipe.in
mkfifo $PIPES_DIR/pipe.out

test_io $PIPES_DIR/pipe.in $PIPES_DIR/pipe.out &
TEST_IO_PID=$!

$SCRIPT_DIR/launch_guest.sh --igvm $SCRIPT_DIR/../bin/coconut-test-qemu.igvm \
    --unit-tests $PIPES_DIR/pipe || true

kill $TEST_IO_PID
rm -rf $PIPES_DIR
