#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run all project fuzzers in parallel for a configurable amount of time.
#
# Requires Bash 5.1 or later for "wait -n -p".

set -u

usage() {
	echo "Usage: $0 [-r|--runtime <seconds>]"
	echo "       $0 -h|--help"
}

fail() {
	echo "ERROR: $1" >&2
	exit 1
}

if ((BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 1))); then
	fail "Bash 5.1 or later is required"
fi

DURATION=600

while [ $# -gt 0 ]; do
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		-r|--runtime)
			if [ $# -lt 2 ]; then
				fail "$1 requires a runtime value"
			fi
			DURATION=$2
			shift 2
			;;
		-r*)
			DURATION=${1#-r}
			shift
			;;
		--runtime=*)
			DURATION=${1#--runtime=}
			shift
			;;
		*)
			usage
			fail "unknown parameter: $1"
			;;
	esac
done

case "$DURATION" in
	''|*[!0-9]*)
		fail "fuzzing duration must be a positive integer"
		;;
	0)
		fail "fuzzing duration must be greater than zero"
		;;
esac

if ! command -v setsid > /dev/null 2>&1; then
	fail "setsid is required to stop all fuzzer child processes"
fi

FUZZ_TARGET_TRIPLE=x86_64-unknown-linux-gnu
RUSTFLAGS_VALUE="-Clinker=clang -Clink-arg=-fuse-ld=lld"

cd "$(git rev-parse --show-toplevel)"

mapfile -t FUZZERS < <(cargo +nightly fuzz list)

if [ "${#FUZZERS[@]}" -eq 0 ]; then
	fail "cargo fuzz list did not return any fuzzer targets"
fi

LOG_DIR="logs/fuzz/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG_DIR"

build_log="$LOG_DIR/build.log"
echo "Building fuzzers, logging to $build_log"
if ! RUSTFLAGS="$RUSTFLAGS_VALUE" \
	cargo +nightly fuzz build --strip-dead-code \
		> "$build_log" 2>&1; then
	echo "Failed to build fuzzers"
	echo "See log: $build_log"
	exit 1
fi

echo "Running fuzzers for $DURATION seconds"

find_fuzzer_binary() {
	local fuzzer=$1
	local binary

	for profile in debug release; do
		binary="target/$FUZZ_TARGET_TRIPLE/$profile/$fuzzer"
		if [ -x "$binary" ]; then
			echo "$binary"
			return 0
		fi
	done

	return 1
}

declare -a PIDS=()
declare -A PID_TO_FUZZER=()
declare -A PID_TO_LOG=()

stop_fuzzers() {
	for pid in "${PIDS[@]}"; do
		kill -- "-$pid" 2> /dev/null || true
	done
}

remove_pid() {
	local remove=$1
	local pid
	local remaining_pids=()

	for pid in "${PIDS[@]}"; do
		if [ "$pid" != "$remove" ]; then
			remaining_pids+=("$pid")
		fi
	done

	PIDS=("${remaining_pids[@]}")
}

cleanup() {
	stop_fuzzers
	wait 2> /dev/null || true
}

trap cleanup EXIT
trap 'exit 130' INT TERM

for fuzzer in "${FUZZERS[@]}"; do
	log_file="$LOG_DIR/${fuzzer}.log"
	fuzzer_binary=$(find_fuzzer_binary "$fuzzer") || \
		fail "built fuzzer binary not found for target: $fuzzer"
	corpus_dir="fuzz/corpus/$fuzzer"
	artifact_dir="fuzz/artifacts/$fuzzer"

	mkdir -p "$corpus_dir" "$artifact_dir"

	echo "Starting fuzzer '$fuzzer', logging to $log_file"
	(
		exec setsid "$fuzzer_binary" "$corpus_dir" \
			"-artifact_prefix=$artifact_dir/" \
			"-max_total_time=$DURATION"
	) > "$log_file" 2>&1 &
	pid=$!
	PIDS+=("$pid")
	PID_TO_FUZZER[$pid]=$fuzzer
	PID_TO_LOG[$pid]=$log_file
done

remaining=${#PIDS[@]}

while [ "$remaining" -gt 0 ]; do
	completed_pid=
	wait -n -p completed_pid "${PIDS[@]}"
	status=$?

	if [ -z "${completed_pid:-}" ]; then
		fail "wait failed before all fuzzers completed"
	fi

	fuzzer=${PID_TO_FUZZER[$completed_pid]}
	log_file=${PID_TO_LOG[$completed_pid]}
	unset "PID_TO_FUZZER[$completed_pid]"
	unset "PID_TO_LOG[$completed_pid]"
	remove_pid "$completed_pid"
	remaining=$((remaining - 1))

	if [ "$status" -eq 0 ]; then
		echo "Fuzzer '$fuzzer' completed successfully"
	else
		echo "Fuzzer '$fuzzer' failed with exit code $status"
		echo "See log: $log_file"
		stop_fuzzers
		wait 2> /dev/null || true
		exit 1
	fi
done

echo "All fuzzers completed successfully"
echo "Logs written to $LOG_DIR"
