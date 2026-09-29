#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Joerg Roedel <jroedel@suse.de>

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SVSM_DIR=$SCRIPT_DIR/..
VSOCK_PORT=12345
VSOCK_CID=10

# Attestation test setup. kbs-test is the throwaway KBS server used to exercise
# the attestation path, see TESTING.md. It is not built by this repository,
# pass its location with --kbs or KBS just like QEMU is passed to
# launch_guest.sh.
#
# Both the port kbs-test listens on and the vsock port aproxy listens on are
# fixed: kbs-test hardcodes the former and SVSM hardcodes the latter
# (ATTEST_DEFAULT_VSOCK_PORT), so neither can be varied per run the way
# --vsock-port can.
: "${KBS:=kbs-test}"
KBS_PORT=8080

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
check_required_tools python3 xxd

# Pre-calculated launch measurement of the image under test, as a hex string.
#
# Both the guest (via IORequest::GetLaunchMeasurement) and kbs-test (via
# --measurement) need this value, and attestation only succeeds if the two
# agree. Compute it in one place so that they cannot drift apart.
launch_measurement() {
    $SVSM_DIR/bin/igvmmeasure $SVSM_DIR/bin/coconut-test-qemu.igvm measure -b
}

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
                launch_measurement | xxd -r -p > $PIPE_IN
                ;;
            # 0x02 Virtio-blk test: send md5 sum of svsm state image to SVSM.
            "02")
              sha256sum "$TEST_DIR/svsm_state.raw" | cut -f 1 -d ' ' | xxd -p -r > "$PIPE_IN"
              ;;
            # 0x03: Virtio-vsock test: open a listening vsock socket, send the server port
            #                          to the guest and a "hello_world" string to SVSM
            #                          using the vsock socket
            "03")
              python3 "$SCRIPT_DIR/test_vsock_server.py" "$TEST_VSOCK_PORT" "$PIPE_IN"
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

# Wait for something to start listening on a localhost TCP port.
wait_for_tcp_port() {
    local port=$1
    local tries=100

    while [ "$tries" -gt 0 ]; do
        if python3 -c "import socket, sys
s = socket.socket()
s.settimeout(1)
sys.exit(s.connect_ex(('127.0.0.1', $port)))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
        tries=$((tries - 1))
    done

    return 1
}

# Bring up the host side of the attestation test: a kbs-test server and the
# aproxy instance that bridges it to the guest's vsock port.
#
# kbs-test is not built by this repository, so it may well be missing. Carry on
# without it: the guest skips the attestation test when it cannot reach a proxy.
start_attestation() {
    if ! command -v "$KBS" > /dev/null 2>&1; then
        echo "WARNING: $KBS not found, the attestation test will be skipped." >&2
        echo "Pass its location with --kbs or KBS to run it, see TESTING.md." >&2
        return
    fi

    check_required_tools "$SVSM_DIR/bin/aproxy"

    # kbs-test only attests a guest whose report carries this measurement.
    # --secret is left out, the test does not check the payload it gets back.
    "$KBS" --measurement "$(launch_measurement)" &
    KBS_PID=$!

    if ! wait_for_tcp_port "$KBS_PORT"; then
        echo "ERROR: kbs-test did not start listening on port $KBS_PORT" >&2
        exit 1
    fi

    $SVSM_DIR/bin/aproxy --protocol kbs \
        --url "http://127.0.0.1:$KBS_PORT" --vsock &
    APROXY_PID=$!

    # aproxy binds its vsock socket during startup and the guest only connects
    # once it has booted, so there is no need to poll for the socket here.
    # Just catch the case where aproxy failed to bind and exited.
    sleep 1
    if ! kill -0 $APROXY_PID 2> /dev/null; then
        echo "ERROR: aproxy exited during startup" >&2
        exit 1
    fi
}

cleanup() {
    for pid in "$TEST_IO_PID" "$APROXY_PID" "$KBS_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2> /dev/null || true
        fi
    done
    rm -rf "$TEST_DIR"
}

TEST_DIR=$(mktemp -d -q)
TEST_IO_PID=""
APROXY_PID=""
KBS_PID=""
# Clean up on any exit path, including a --timeout kill or a Ctrl-C, so that
# the background servers do not outlive the script.
trap cleanup EXIT

mkfifo $TEST_DIR/pipe.in
mkfifo $TEST_DIR/pipe.out
# Create a raw disk image (512kB in size) for virtio-blk tests containing random data
dd if=/dev/urandom of="$TEST_DIR/svsm_state.raw" bs=512 count=1024

LAUNCH_GUEST_ARGS=""
TIMEOUT_CMD=""

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
    --timeout)
      echo "Running tests with timeout: $2"
      TIMEOUT_CMD="timeout --foreground $2"
      shift
      shift
      ;;
    --kbs)
      KBS="$2"
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

start_attestation

test_io $TEST_DIR/pipe.in $TEST_DIR/pipe.out $VSOCK_PORT &
TEST_IO_PID=$!

svsm_exit_code=0

$TIMEOUT_CMD \
    $SCRIPT_DIR/launch_guest.sh \
        --igvm $SCRIPT_DIR/../bin/coconut-test-qemu.igvm \
        --state "$TEST_DIR/svsm_state.raw" \
        --vsock "$VSOCK_CID" \
        --unit-tests $TEST_DIR/pipe \
        $LAUNCH_GUEST_ARGS "$@" || svsm_exit_code=$?

# SVSM writes 0x10 to the QEMU exit port when all tests passed.
# This results in QEMU returning 0x21 ((0x10 << 1) | 1)
if [[ $svsm_exit_code -eq 0x21 ]]; then
    echo "All tests passed"
    exit_value=0
elif [[ $svsm_exit_code -eq 124 && -n "$TIMEOUT_CMD" ]]; then
    echo "Test Failed: timeout"
    exit_value=1
else
    echo "Test Failed with exit code: $svsm_exit_code"
    exit_value=1
fi

exit $exit_value
