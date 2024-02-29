#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (c) 2023 SUSE LLC
#
# Author: Carlos López <carlos.lopez@suse.com>
#
# Simple script to check that a commit has a Signed-off-by trailer and a
# nonempty commit body.

matches_any() {
	needle=$1
	haystack=$2

	while IFS= read -r item; do
		if [ "$needle" = "$item" ]; then
			return 0
		fi
	done < <(printf '%s\n' "$haystack")

	return 1
}

# Check that the body for the given commit is not empty
nonempty_body() {
	body=$(git show --no-patch --format="%b" "$1" | sed '/^ *$/d')
	trailers=$(git show --no-patch --format="%(trailers:only)" "$1")

	body_len=$(echo "$body" | wc -l)
	trailer_len=$(echo "$trailers" | wc -l)

	# If the body is the same length as the trailers it means the body is empty
	[ "$body_len" = "$trailer_len" ] && return 1
	return 0
}

if [ $# -lt 1 ]; then
	echo "Usage: $0 <start_commit> [<end_commit>]"
	exit 1
fi

start=$1
end=$2

commits=$(git log --no-merges "${start}".."${end}" --format="%H")
for c in ${commits[@]}; do

	echo "Checking $c"

	nonempty_body "$c"
	if [ "$?" != "0" ]; then
		echo "Message body is empty for commit $c"
		exit 1
	fi

	commit_email=$(git show --no-patch --format="%ae" "$c" || exit 1)
	commit_name=$(git show --no-patch --format="%an" "$c" || exit 1)
	sign_names=$(git show --no-patch "$c" | sed -nr 's/^[[:space:]]*Signed-off-by: (.*) <(.*)>/\1/p' || exit 1)
	sign_emails=$(git show --no-patch "$c" | sed -nr 's/^[[:space:]]*Signed-off-by: (.*) <(.*)>/\2/p' || exit 1)

	matches_any "$commit_name" "$sign_names"
	if [ "$?" != "0" ]; then
		echo "Author name mismatch on commit $c"
		echo "    Commit author name: $commit_name"
		echo "    Signed-off-by name(s):" $sign_names
		exit 1
	fi

	matches_any "$commit_email" "$sign_emails"
	if [ "$?" != "0" ]; then
		echo "Author email mismatch on commit $c"
		echo "    Commit author email: $commit_email"
		echo "    Signed-off-by email(s):" $sign_emails
		exit 1
	fi

done

exit 0
