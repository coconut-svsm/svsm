#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2025 Red Hat, Inc.
#
# Author: Oliver Steffen <osteffen@redhat.com>
set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# Default mode is regular testing
MODE="regular"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --attest)
            MODE="attest"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--attest]"
            exit 1
            ;;
    esac
done

# Set test parameters based on mode
if [[ "$MODE" == "attest" ]]; then
    TEST_SCRIPT="test-in-svsm-attest.sh"
    SUCCESS="Attestation test passed"
    TIMEOUT=240s
else
    TEST_SCRIPT="test-in-svsm.sh"
    SUCCESS="All tests passed"
    TIMEOUT=180s
fi

# Clone STDOUT for live log reporting
exec 3>&1

echo "================================================================================"
timeout $TIMEOUT \
  grep -q -m 1 "$SUCCESS" \
  <("$SCRIPT_DIR/$TEST_SCRIPT" --nocc </dev/null 2>&1 | tee /proc/self/fd/3)
RES=$?
echo "================================================================================"

case $RES in
0)
  echo "Test Pass!"
  exit 0
  ;;
124)
  echo "Test failed: timeout"
  exit 1
  ;;
*)
  echo "Test failed: Unknown error"
  exit 1
  ;;
esac
