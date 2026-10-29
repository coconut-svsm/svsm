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
# the attestation path, see TESTING.md. It is not built by this repository and
# the attestation test is opt-in: it only runs when the location of kbs-test is
# passed with --kbs or KBS.
#
# Both the port kbs-test listens on and the vsock port aproxy listens on are
# fixed: kbs-test hardcodes the former and SVSM hardcodes the latter
# (ATTEST_DEFAULT_VSOCK_PORT), so neither can be varied per run the way
# --vsock-port can.
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
            # 0x04: Attestation test: tell SVSM whether start_attestation()
            #       started the attestation servers (1 byte, 01 if it did).
            #       It exits the script on failure, so KBS being set is enough.
            "04")
              if [ -n "$KBS" ]; then
                  echo 01 | xxd -r -p > "$PIPE_IN"
              else
                  echo 00 | xxd -r -p > "$PIPE_IN"
              fi
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

# Check whether something is listening on a localhost TCP port.
tcp_port_in_use() {
    python3 -c "import socket, sys
s = socket.socket()
s.settimeout(1)
sys.exit(s.connect_ex(('127.0.0.1', $1)))" 2> /dev/null
}

# Wait for process $2 to start listening on localhost TCP port $1.
#
# The caller must make sure the port is free beforehand, otherwise another
# listener would be mistaken for this process. Bail out as soon as the process
# exits rather than waiting for the timeout.
wait_for_tcp_port() {
    local port=$1
    local pid=$2
    local tries=100

    while [ "$tries" -gt 0 ]; do
        if ! kill -0 "$pid" 2> /dev/null; then
            return 1
        fi
        if tcp_port_in_use "$port"; then
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
# The attestation test is opt-in. Without a kbs-test location, start nothing:
# test_io() then tells the guest to skip the attestation test.
start_attestation() {
    local measurement

    if [ -z "$KBS" ]; then
        echo "KBS not set, the attestation test will be skipped, see TESTING.md." >&2
        return
    fi

    check_required_tools "$KBS" "$SVSM_DIR/bin/aproxy" "$SVSM_DIR/bin/igvmmeasure"

    # kbs-test only attests a guest whose report carries this measurement.
    # Compute it before starting kbs-test: a command substitution inside a
    # background job is not covered by set -e, so a failure would start
    # kbs-test with an empty measurement.
    if ! measurement=$(launch_measurement); then
        echo "ERROR: failed to compute the launch measurement" >&2
        exit 1
    fi

    # kbs-test listens on a fixed port. If something else already holds it,
    # kbs-test fails to bind and aproxy would talk to that listener instead.
    if tcp_port_in_use "$KBS_PORT"; then
        echo "ERROR: port $KBS_PORT is already in use, cannot start kbs-test" >&2
        exit 1
    fi

    # --secret is left out, the test does not check the payload it gets back.
    "$KBS" --measurement "$measurement" &
    KBS_PID=$!

    if ! wait_for_tcp_port "$KBS_PORT" "$KBS_PID"; then
        echo "ERROR: kbs-test did not start listening on port $KBS_PORT" >&2
        exit 1
    fi

    $SVSM_DIR/bin/aproxy --protocol kbs \
        --url "http://127.0.0.1:$KBS_PORT" --vsock &
    APROXY_PID=$!

    # aproxy binds its vsock socket during startup and the guest only connects
    # once it has booted, so there is no need to wait for it here. If aproxy
    # fails, the guest fails the attestation test.
}

cleanup() {
    for pid in "$TEST_IO_PID" "$APROXY_PID" "$KBS_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2> /dev/null || true
        fi
    done
    # Reap the servers so that kbs-test has released its port by the time the
    # script returns, otherwise an immediate rerun could fail to bind it.
    for pid in "$APROXY_PID" "$KBS_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2> /dev/null || true
        fi
    done
    rm -rf "$TEST_DIR"
}

TEST_DIR=$(mktemp -d -q)
TEST_IO_PID=""
APROXY_PID=""
KBS_PID=""
# Clean up on any exit path, including an early exit on error, a Ctrl-C or a
# SIGTERM (e.g. a cancelled CI job), so that test_io(), aproxy and kbs-test do
# not outlive the script. QEMU is not covered: launch_guest.sh starts it as its
# own child.
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
