#!/usr/bin/env bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [[ $1 == "debug" ]]; then
    LOG_FILE="ovmf_debug.build"
else
    LOG_FILE="ovmf_release.build"
fi
rm -f $LOG_FILE

pushd $SCRIPT_DIR/../edk2

export PYTHON3_ENABLE=TRUE
export PYTHON_COMMAND=python3

# First build requires some initialisation
if [ ! -d "$SCRIPT_DIR/../edk2/BaseTools/Source/C/bin" ]; then
    echo "Building OVMF base tools."
    make -C BaseTools -j $(nproc) > $LOG_FILE 2> $LOG_FILE
fi

unset WORKSPACE
source edksetup.sh --reconfig >> $LOG_FILE 2>> $LOG_FILE

if [[ $1 == "debug" ]]; then
    echo "Building OVMF(debug). Build output logged to edk2/$LOG_FILE."
    build -a X64 -b DEBUG -t GCC5 -D DEBUG_ON_SERIAL_PORT -D DEBUG_VERBOSE -p OvmfPkg/OvmfPkgX64.dsc >> $LOG_FILE 2>> $LOG_FILE
else
    echo "Building OVMF(release). Build output logged to edk2/$LOG_FILE."
    build -a X64 -b RELEASE -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc >> $LOG_FILE 2>> $LOG_FILE
fi
popd
