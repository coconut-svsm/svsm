#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Joerg Roedel <jroedel@suse.de>

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ "$QEMU" == "" ]; then
	echo "Set QEMU environment variable to QEMU installation path" && exit 1
fi

$SCRIPT_DIR/launch_guest.sh --igvm $SCRIPT_DIR/../bin/coconut-test-qemu.igvm