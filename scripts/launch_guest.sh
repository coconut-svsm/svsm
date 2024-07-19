#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2024 SUSE LLC
#
# Author: Roy Hopkins <roy.hopkins@suse.com>
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

: "${QEMU:=qemu-system-x86_64}"
: "${IGVM:=$SCRIPT_DIR/../bin/coconut-qemu.igvm}"

C_BIT_POS=`$SCRIPT_DIR/../utils/cbit`
DEBUG_SERIAL=""
QEMU_EXIT_DEVICE=""
QEMU_TEST_IO_DEVICE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -q|--qemu)
      QEMU="$2"
      shift
      shift
      ;;
    -i|--igvm)
      IGVM="$2"
      shift
      shift
      ;;
    --image)
      IMAGE="$2"
      shift
      shift
      ;;
    -d|--debugserial)
      DEBUG_SERIAL="-serial pty"
      shift
      ;;
    --unit-tests)
      QEMU_EXIT_DEVICE="-device isa-debug-exit,iobase=0xf4,iosize=0x04"
      QEMU_TEST_IO_DEVICE="-device pc-testdev"
      shift
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
done

# Split the QEMU version number so we can specify the correct parameters
QEMU_VERSION=`$QEMU --version | grep -Po '(?<=version )[^ ]+'`
QEMU_MAJOR=${QEMU_VERSION%%.*}
QEMU_BUILD=${QEMU_VERSION##*.}
QEMU_MINOR=${QEMU_VERSION##$QEMU_MAJOR.}
QEMU_MINOR=${QEMU_MINOR%%.$QEMU_BUILD}

# The QEMU machine and memory command line changed after QEMU 8.2.0 from
# the coconut-svsm git repository.
if (( QEMU_MAJOR >= 9 )); then
  MACHINE=q35,confidential-guest-support=sev0,memory-backend=mem0,igvm-cfg=igvm0
  IGVM_OBJECT=
  MEMORY=memory-backend-memfd,size=8G,id=mem0,share=true,prealloc=false,reserve=false
  IGVM_OBJECT="-object igvm-cfg,id=igvm0,file=$IGVM"
  INIT_FLAGS=
  IGVM_FILE=
elif (( (QEMU_MAJOR > 8) || ((QEMU_MAJOR == 8) && (QEMU_MINOR >= 2)) )); then
  MACHINE=q35,confidential-guest-support=sev0,memory-backend=mem0
  MEMORY=memory-backend-memfd,size=8G,id=mem0,share=true,prealloc=false,reserve=false
  IGVM_FILE=",igvm-file=$IGVM"
  IGVM_OBJECT=
  INIT_FLAGS=,init-flags=5
else
  MACHINE=q35,confidential-guest-support=sev0,memory-backend=mem0,kvm-type=protected
  MEMORY=memory-backend-memfd-private,size=8G,id=mem0,share=true
  IGVM_OBJECT=
  INIT_FLAGS=,init-flags=5
fi

# Setup a disk if an image has been specified
if [ ! -z $IMAGE ]; then
  IMAGE_DISK="-drive file=$IMAGE,if=none,id=disk0,format=qcow2,snapshot=on \
    -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=on \
    -device scsi-hd,drive=disk0,bootindex=0"
fi

if [ "$EUID" -ne 0 ]; then
	SUDO_CMD="sudo"
else
	SUDO_CMD=""
fi

echo "============================="
echo "Launching SVSM guest"
echo "============================="
echo "QEMU:         ${QEMU}"
echo "QEMU Version: ${QEMU_VERSION}"
echo "IGVM:         ${IGVM}"
echo "IMAGE:        ${IMAGE}"
echo "============================="
echo "Press Ctrl-] to interrupt"
echo "============================="

# Remap Ctrl-C to Ctrl-] to allow the guest to handle Ctrl-C.
stty intr ^]

$SUDO_CMD \
  $QEMU \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine $MACHINE \
    -object $MEMORY \
    -object sev-snp-guest,id=sev0,cbitpos=$C_BIT_POS,reduced-phys-bits=1$INIT_FLAGS$IGVM_FILE \
    $IGVM_OBJECT \
    -smp 4 \
    -no-reboot \
    -netdev user,id=vmnic -device e1000,netdev=vmnic,romfile= \
    $IMAGE_DISK \
    -nographic \
    -monitor none \
    -serial stdio \
    $DEBUG_SERIAL \
    $QEMU_EXIT_DEVICE \
    $QEMU_TEST_IO_DEVICE

stty intr ^C
