#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2026 Tanya Agarwal <tanyaagarwal25699@gmail.com>
#
# Script to check that new files added in commit contain
# SPDX-License-Identifier header.

# Always run from repository root
cd "$(git rev-parse --show-toplevel)"

if [ $# -lt 1 ]; then
	echo "Usage: $0 <start_commit> [<end_commit>]"
	exit 1
fi

start=$1
end=$2

new_files=$(git diff --name-only --diff-filter=A "${start}".."${end}")

# Nothing to check if no new files
if [ -z "$new_files" ]; then
	exit 0
fi

missing=0
for file in $new_files; do
	[ -f "$file" ] || continue

	case "$file" in
		*.c|*.h|*.rs|*.sh|*.py|*.toml|*.yml|*.yaml)
			if ! grep -q "SPDX-License-Identifier" "$file"; then
				echo "ERROR: Missing SPDX header in $file"
				((missing++))
			fi
			;;
	esac
done

if (($missing >  0)); then
	echo "SPDX headers not found in total $missing files"
	exit 1
fi

exit 0
