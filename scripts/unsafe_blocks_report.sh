#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CLIPPY_SAFETY_MSG="missing a safety comment"

CLIPPY_FILE=
TMP_FILE=
QUIET=0

ALL=1
MODULE=0
TOTAL=0

cleanup() {
  if [ -n "${TMP_FILE}" ]; then
    rm "${TMP_FILE}"
  fi
}
trap cleanup EXIT

function usage
{
    echo -e "usage: $0 [OPTION...]"
    echo -e ""
    echo -e "Print statistics about undocumented unsafe blocks"
    echo -e ""
    echo -e "Generic options:"
    echo -e " -f, --file FILENAME  Use the specified file, instead of running clippy"
    echo -e " -q, --quiet          Print just stats without log messages"
    echo -e " -h, --help           Print this help"
    echo -e ""
    echo -e "By default all stats are printed; to select only some of them,"
    echo -e "please use the following options:"
    echo -e " -m, --module         Undocumented unsafe blocks per module"
    echo -e " -t, --total          Total number of undocumented unsafe blocks"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -f | --file)
            CLIPPY_FILE="$2"
            shift
        ;;
        -q | --quiet)
            QUIET=1
        ;;
        -m | --module)
            ALL=0
            MODULE=1
        ;;
        -t | --total)
            ALL=0
            TOTAL=1
        ;;
        -h | --help)
            usage
            exit
            ;;
        -*|--*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            echo "Invalid parameter $1"
            exit 1
            ;;
    esac
    shift
done

log() {
  if [ "${QUIET}" == "0" ]; then
    echo -e "$@"
  fi
}

clippy_unsafe_blocks_per_module() {
    grep -A 1 "${CLIPPY_SAFETY_MSG}" "$1" | grep "\-->" | awk '{print $2}' | \
        sort | uniq | cut -d':' -f1 | \
        awk -F'/' '{
            module="";
            for(i=1; i <= NF; i++) {
                module=module "/" $i;
                print module
            }
        }' | sort | uniq -c
}

clippy_unsafe_blocks_total() {
    grep -A 1 "${CLIPPY_SAFETY_MSG}" "$1" | grep "\-->" | awk '{print $2}' | \
        sort | uniq | wc -l
}

if [ -z "${CLIPPY_FILE}" ]; then
    log "Running \`make clippy\`..."
    TMP_FILE=$(mktemp)
    make -C "${SCRIPT_DIR}/.." clippy CLIPPY_OPTIONS="--quiet --color=never" \
        UNSAFE_BLOCKS=1 2>"${TMP_FILE}"
    CLIPPY_FILE="${TMP_FILE}"
    log ""
fi

if [[ "${ALL}" == "1" || "${MODULE}" == "1" ]]; then
    log "Undocumented unsafe blocks per module\n"
    clippy_unsafe_blocks_per_module "${CLIPPY_FILE}"
    log ""
fi

if [[ "${ALL}" == "1" || "${TOTAL}" == "1" ]]; then
    log "Total number of undocumented unsafe blocks\n"
    clippy_unsafe_blocks_total "${CLIPPY_FILE}"
    log ""
fi
