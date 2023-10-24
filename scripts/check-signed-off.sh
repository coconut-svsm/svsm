#!/bin/bash

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

if [ $# -lt 1 ]; then
	echo "Usage: $0 <start_commit> [<end_commit>]"
	exit 1
fi

start=$1
end=$2

commits=$(git log "${start}".."${end}" --pretty=format:"%H")
for c in ${commits[@]}; do

	echo "Checking $c"

	# If a commit has more than more parent it is a merge commit, so ignore it
	parents=$(git cat-file -p "$c" | grep -c parent)
	[ "$parents" -gt "1" ] && continue

	commit_email=$(git show --no-patch --pretty="format:%ae" "$c" || exit 1)
	commit_name=$(git show --no-patch --pretty="format:%an" "$c" || exit 1)
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
