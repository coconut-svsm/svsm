#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <start_commit> [<end_commit>]"
	exit 1
fi

start=$1
end=$2

commits=$(git log "${start}".."${end}" --pretty=format:"%H")
for c in ${commits[@]}; do

	echo "Checking $c"

	commit_email=$(git show --no-patch --pretty="format:%ae" "$c" || exit 1)
	commit_name=$(git show --no-patch --pretty="format:%an" "$c" || exit 1)
	sign_name=$(git show --no-patch "$c" | sed -nr 's/^[[:space:]]*Signed-off-by: (.*) <(.*)>/\1/p' || exit 1)
	sign_email=$(git show --no-patch "$c" | sed -nr 's/^[[:space:]]*Signed-off-by: (.*) <(.*)>/\2/p' || exit 1)

	if [ "$commit_name" != "$sign_name" ]; then
		echo "Author name mismatch on commit $c"
		echo "    Commit author name: $commit_name"
		echo "    Signed-off-by name: $sign_name"
		exit 1
	fi

	if [ "$commit_email" != "$sign_email" ]; then
		echo "Author email mismatch on commit $c"
		echo "    Commit author name: $commit_name"
		echo "    Signed-off-by name: $sign_name"
		exit 1
	fi

done

exit 0
