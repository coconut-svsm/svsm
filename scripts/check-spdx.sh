#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2026 Tanya Agarwal <tanyaagarwal25699@gmail.com>
#
# Script to check that files contain an SPDX-License-Identifier header.
#
# Modes:
#   --all				check every tracked file.
#   <start_commit> [<end_commit>]	check only files added in this commit range.
#					<end_commit> defaults to HEAD.

set -e

# Always run from repository root
cd "$(git rev-parse --show-toplevel)"

if [ $# -lt 1 ]; then
	echo "Usage: $0 --all"
	echo "       $0 <start_commit> [<end_commit>]"
	exit 1
fi

if [ "$1" = "--all" ]; then
	files=$(git ls-files)
else
	start=$1
	end=${2:-HEAD}
	files=$(git diff --name-only --diff-filter=AM "${start}".."${end}")
fi

# Nothing to check if no new files
if [ -z "$files" ]; then
	echo "No files to check for SPDX-License-Identifier header."
	exit 0
fi

missing=0

fail() {
	echo "ERROR: $1"
	missing=$((missing + 1))
}

for file in $files; do
	[ -f "$file" ] || continue

	case "$file" in
		*.c|*.h|*.rs|*.sh|*.py|*.lds|*.S)
			header=$(head -n 5 "$file")
			if ! grep -q "SPDX-License-Identifier" <<< "$header"; then
				fail "Missing SPDX header in $file"
			elif ! grep -qE "SPDX-License-Identifier:.*\bMIT\b" <<< "$header"; then
				fail "Missing MIT license in SPDX header in $file"
			fi
			;;
	esac
done

if (($missing > 0)); then
	echo "$missing file(s) have SPDX-License-Identifier header issues."
	exit 1
fi

echo "All checked file(s) contain a valid SPDX-License-Identifier header."
exit 0
