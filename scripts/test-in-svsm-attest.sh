#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2026 Coconut-SVSM Authors
#
# Run in-SVSM tests with attestation enabled by starting a local kbs-test
# server and aproxy instance.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
SVSM_DIR="$SCRIPT_DIR/.."

: "${TEST_IGVM:=$SVSM_DIR/bin/coconut-test-qemu-attest.igvm}"
: "${KBS_TEST_URL:=http://127.0.0.1:8080}"
# Test-only placeholder secret; not used in production.
: "${KBS_TEST_SECRET:=00112233445566778899aabbccddeeff}"
: "${KBS_TEST_STARTUP_TIMEOUT:=300}"
: "${APROXY_STARTUP_TIMEOUT:=30}"

declare -a TEST_IN_SVSM_ARGS
declare -a LAUNCH_GUEST_ARGS
declare -a KBS_TEST_CMD

TEST_IN_SVSM_ARGS=()
LAUNCH_GUEST_ARGS=()
KBS_TEST_CMD=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --nocc)
            TEST_IN_SVSM_ARGS+=("--nocc")
            shift
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                LAUNCH_GUEST_ARGS+=("$1")
                shift
            done
            ;;
        *)
            echo "Invalid parameter $1"
            exit 1
            ;;
    esac
done

if [[ -n "${KBS_TEST_BIN:-}" ]]; then
    KBS_TEST_CMD=("$KBS_TEST_BIN")
elif [[ -n "${KBS_TEST_DIR:-}" ]]; then
    KBS_TEST_CMD=(cargo run --manifest-path "$KBS_TEST_DIR/Cargo.toml" --)
elif command -v kbs-test >/dev/null 2>&1; then
    KBS_TEST_CMD=(kbs-test)
else
    echo "Unable to find kbs-test. Set KBS_TEST_BIN or KBS_TEST_DIR."
    exit 1
fi

for bin in "$SVSM_DIR/bin/igvmmeasure" "$SVSM_DIR/bin/aproxy"; do
    if [[ ! -x "$bin" ]]; then
        echo "Required executable not found: $bin"
        exit 1
    fi
done

if [[ ! -f "$TEST_IGVM" ]]; then
    echo "Required test image not found: $TEST_IGVM"
    exit 1
fi

TEST_DIR=$(mktemp -d -q)
KBS_LOG="$TEST_DIR/kbs-test.log"
APROXY_LOG="$TEST_DIR/aproxy.log"
SVSM_LOG="$TEST_DIR/test-in-svsm.log"
APROXY_SOCKET="$TEST_DIR/svsm-proxy.sock"
KBS_PID=0
APROXY_PID=0

cleanup() {
    if [[ $APROXY_PID -ne 0 ]]; then
        kill "$APROXY_PID" 2>/dev/null || true
    fi
    if [[ $KBS_PID -ne 0 ]]; then
        kill "$KBS_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1"
    local pid="$2"
    local timeout="$3"
    local deadline=$((SECONDS + timeout))
    while (( SECONDS < deadline )); do
        if curl -sS --max-time 1 "$url" >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            return 1
        fi
        sleep 0.2
    done
    return 1
}

wait_for_socket() {
    local socket="$1"
    local pid="$2"
    local timeout="$3"
    local deadline=$((SECONDS + timeout))
    while (( SECONDS < deadline )); do
        if [[ -S "$socket" ]]; then
            return 0
        fi
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            return 1
        fi
        sleep 0.2
    done
    return 1
}

MEASUREMENT=$("$SVSM_DIR/bin/igvmmeasure" "$TEST_IGVM" measure -b)

"${KBS_TEST_CMD[@]}" \
    --measurement "$MEASUREMENT" \
    --secret "$KBS_TEST_SECRET" >"$KBS_LOG" 2>&1 &
KBS_PID=$!

if ! wait_for_http "$KBS_TEST_URL" "$KBS_PID" "$KBS_TEST_STARTUP_TIMEOUT"; then
    echo "Timed out waiting for kbs-test at $KBS_TEST_URL"
    cat "$KBS_LOG"
    exit 1
fi

"$SVSM_DIR/bin/aproxy" \
    --protocol kbs \
    --url "$KBS_TEST_URL" \
    --unix "$APROXY_SOCKET" \
    --force >"$APROXY_LOG" 2>&1 &
APROXY_PID=$!

if ! wait_for_socket "$APROXY_SOCKET" "$APROXY_PID" "$APROXY_STARTUP_TIMEOUT"; then
    echo "Timed out waiting for aproxy socket: $APROXY_SOCKET"
    cat "$APROXY_LOG"
    exit 1
fi

set +e
TEST_IGVM="$TEST_IGVM" \
    "$SCRIPT_DIR/test-in-svsm.sh" \
    ${TEST_IN_SVSM_ARGS[@]+"${TEST_IN_SVSM_ARGS[@]}"} \
    -- \
    --aproxy "$APROXY_SOCKET" \
    ${LAUNCH_GUEST_ARGS[@]+"${LAUNCH_GUEST_ARGS[@]}"} 2>&1 | tee "$SVSM_LOG"
SVSM_EXIT=${PIPESTATUS[0]}
set -e

if [[ $SVSM_EXIT -ne 0 ]]; then
    echo "SVSM test failed with status $SVSM_EXIT"
    echo "--- aproxy log ---"
    cat "$APROXY_LOG"
    echo "--- kbs-test log ---"
    cat "$KBS_LOG"
    exit $SVSM_EXIT
fi

if ! grep -q "attestation successful" "$SVSM_LOG"; then
    echo "Attestation success message not found in SVSM output"
    echo "--- aproxy log ---"
    cat "$APROXY_LOG"
    echo "--- kbs-test log ---"
    cat "$KBS_LOG"
    exit 1
fi

echo "Attestation test passed"
