#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) Microsoft Corporation
#
# Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
# A script to format code inside verus macro.

for f in `find ./ -type f -name "*.verus.rs"`
do
output=$(verusfmt $f $@ 2>&1)
if [ $? -ne 0 ]; then
    # Check if the output contains "Failed to parse"
    if echo "$output" | grep -q "Failed to parse"; then
      echo "Continuing despite parse failure: $output"
    else
      echo "Error occurred: $output"
      exit 1
    fi
fi
done
