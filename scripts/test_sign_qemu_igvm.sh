#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2024 SUSE LLC
#
# Author: Roy Hopkins <roy.hopkins@suse.com>
#
# Sign the QEMU IGVM file with test keys, generating
# the test keys if they do not exist.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SVSM_DIR=$SCRIPT_DIR/..

# Generate the test keys if they do not already exist
if [ ! -d $SVSM_DIR/testkeys ] || [ ! -f $SVSM_DIR/testkeys/id_key.pem ]; then
    echo "Generating test keys"
    $SCRIPT_DIR/gen_igvm_signing_keys.sh
fi

echo "Signing file: $SVSM_DIR/bin/coconut-qemu.igvm"
$SVSM_DIR/bin/igvmmeasure $SVSM_DIR/bin/coconut-qemu.igvm sign --output bin/coconut-qemu-signed.igvm --id-key $SVSM_DIR/testkeys/id_key.pem --author-key $SVSM_DIR/testkeys/author_key.pem
