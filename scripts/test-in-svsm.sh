#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Joerg Roedel <jroedel@suse.de>

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VSOCK_PORT=12345
VSOCK_CID=10

# Verify the tools used by this script and its callees are available on the
# host before launching the guest. Missing tools surface as opaque panics
# from inside the SVSM (see issue #1042), so check up front.
check_required_tools() {
    local missing=()
    for tool in "$@"; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "ERROR: missing required tools: ${missing[*]}" >&2
        echo "Install them on the host before running this script." >&2
        exit 1
    fi
}

# Only the non-coreutils binaries are listed here, since coreutils is assumed to
# be installed. Add any future non-coreutils dependencies to this list.
check_required_tools ncat xxd ss

test_io(){
    PIPE_IN=$1
    PIPE_OUT=$2
    while read -r -n 1 -u 3 BYTE; do
        TEST=$(printf '%s' "$BYTE" | xxd -p)
        TEST_VSOCK_PORT=$3
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
            # 0x03: Virtio-vsock test: open a listening vsock socket, send the server port
            #                          to the guest and a "hello_world" string to SVSM
            #                          using the vsock socket
            "03")
              # virtio-vsock in svsm does not handle half duplex connections.
              # This is why we need to use `--no-shutdown` that prevents ncat from sending a
              # partial shutdown after it has no more bytes to send.
              echo -n "hello_world" | ncat --no-shutdown -l --vsock -p $TEST_VSOCK_PORT > /dev/null &
              echo $! >> "$NCAT_PIDS_FILE"
              NCAT_READY=false
              # Wait until ncat is ready for listening
              for _ in $(seq 1 50); do
                  if ss --numeric --listening --no-header --vsock | grep -q ":$TEST_VSOCK_PORT"; then
                      NCAT_READY=true
                      break
                  fi
                  sleep 0.1
              done
              if [ "$NCAT_READY" = false ]; then
                  echo "ncat failed to start listening on vsock port $TEST_VSOCK_PORT"
                  # use VMADDR_PORT_ANY to signal the guest that an error has occurred
                  TEST_VSOCK_PORT=$((0xFFFFFFFF))
              fi
              # write port number as a zero-padded 8-char hex string
              printf '%08x' "$TEST_VSOCK_PORT" | xxd -p -r > "$PIPE_IN"
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
NCAT_PIDS_FILE="$TEST_DIR/ncat_pids"
mkfifo $TEST_DIR/pipe.in
mkfifo $TEST_DIR/pipe.out
# Create a raw disk image (512kB in size) for virtio-blk tests containing random data
dd if=/dev/urandom of="$TEST_DIR/svsm_state.raw" bs=512 count=1024

LAUNCH_GUEST_ARGS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --nocc)
      LAUNCH_GUEST_ARGS+="--nocc "
      shift
      ;;
    --vsock-cid)
      VSOCK_CID="$2"
      shift
      shift
      ;;
    --vsock-port)
      VSOCK_PORT="$2"
      shift
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Invalid parameter $1"
      exit 1
      ;;
  esac
done

test_io $TEST_DIR/pipe.in $TEST_DIR/pipe.out $VSOCK_PORT &
TEST_IO_PID=$!

$SCRIPT_DIR/launch_guest.sh --igvm $SCRIPT_DIR/../bin/coconut-test-qemu.igvm \
    --state "$TEST_DIR/svsm_state.raw" \
    --vsock "$VSOCK_CID" \
    --unit-tests $TEST_DIR/pipe \
    $LAUNCH_GUEST_ARGS "$@" || svsm_exit_code=$?

# SVSM writes 0x10 to the QEMU exit port when all tests passed.
# This results in QEMU returning 0x21 ((0x10 << 1) | 1)
if [[ $svsm_exit_code -eq 0x21 ]]; then
    echo "All tests passed"
    exit_value=0
else
    echo "Test Failed"
    exit_value=1
fi

kill $TEST_IO_PID 2> /dev/null || true
# Kill ncat processes spawned by test_io. NCAT_PID was set inside a
# subshell (test_io runs in background) so it is not visible here.
# Read the PIDs from the file instead.
if [ -f "$NCAT_PIDS_FILE" ]; then
    while read -r pid; do
        kill "$pid" 2> /dev/null || true
    done < "$NCAT_PIDS_FILE"
fi
rm -rf $TEST_DIR

exit $exit_value
