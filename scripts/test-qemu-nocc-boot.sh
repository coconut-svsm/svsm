#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2025 Red Hat, Inc.
#
# Author: Oliver Steffen <osteffen@redhat.com>
set -ue

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# When we see this string on the serial output, consider
# SVSM booted and the test passed.
SUCCESS="Terminating task init"

# Fail the test after this timeout
TIMEOUT=4s

# Clone STDOUT for live log reporting
exec 3>&1

echo "================================================================================"
timeout $TIMEOUT \
  grep -q -m 1 "$SUCCESS" \
  <("$SCRIPT_DIR/launch_guest.sh" --nocc | tee /proc/self/fd/3)
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
