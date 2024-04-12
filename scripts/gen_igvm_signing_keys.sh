#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2024 SUSE LLC
#
# Author: Roy Hopkins <roy.hopkins@suse.com>
#
# Generate keys for testing that can be used for signing an IGVM file
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

mkdir -p $SCRIPT_DIR/../testkeys/
openssl ecparam -name secp384r1 -genkey -noout -out $SCRIPT_DIR/../testkeys/id_key.pem
openssl ecparam -name secp384r1 -genkey -noout -out $SCRIPT_DIR/../testkeys/author_key.pem
