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
: "${KERNEL_BIN:="${guest_kernel}"}" ## Incase your work environment is ubuntu, guest_kernel is your ubuntu kernel image "vmlinuz-6.8.0-snp-guest-bc4de28e0cc1" o
: "${INITRD_BIN:="${GENERATED_INITRD_BIN}"}" #Incase your work environment is ubuntu, GENERATED_INITRD_BIN is your generated guest linux "initrd.img-6.8.0-snp-guest-bc4de28e0cc1"

GUEST_ROOT_LABEL="${GUEST_ROOT_LABEL:-cloudimg-rootfs}"
GUEST_KERNEL_APPEND="root=LABEL=${GUEST_ROOT_LABEL} ro console=ttyS0"


C_BIT_POS=`$SCRIPT_DIR/../utils/cbit`
COM1_SERIAL="-serial stdio" # console
COM2_SERIAL="-serial null"  # debug
COM3_SERIAL="-serial null"  # used by hyper-v
COM4_SERIAL="-serial null"  # used by in-SVSM tests
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
      --kernel)
      KERNEL_BIN="$2"
      shift
      shift
      ;;
    --initrd)
      INITRD_BIN="$2"
      shift
      shift
      ;;
    --append)
      GUEST_KERNEL_APPEND="$2"
      shift
      shift
      ;;
    -d|--debugserial)
      COM2_SERIAL="-serial pty"
      shift
      ;;
    --unit-tests)
      QEMU_EXIT_DEVICE="-device isa-debug-exit,iobase=0xf4,iosize=0x04"
      QEMU_TEST_IO_DEVICE="-device pc-testdev"
      COM4_SERIAL="-chardev pipe,id=test,path=$2 -serial chardev:test"
      shift
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
if (( (QEMU_MAJOR > 8) || ((QEMU_MAJOR == 8) && (QEMU_MINOR >= 2)) )); then
  MACHINE=q35,confidential-guest-support=sev0,memory-backend=mem0
  MEMORY=memory-backend-memfd,size=8G,id=mem0,share=true,prealloc=false,reserve=false
else
  MACHINE=q35,confidential-guest-support=sev0,memory-backend=mem0,kvm-type=protected
  MEMORY=memory-backend-memfd-private,size=8G,id=mem0,share=true
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
echo "KERNEL:       ${KERNEL_BIN}"
echo "INITRD:       ${INITRD_BIN}"
echo "APPEND:       ${GUEST_KERNEL_APPEND}"
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
    -object sev-snp-guest,id=sev0,cbitpos=$C_BIT_POS,reduced-phys-bits=1,init-flags=5,igvm-file=$IGVM \
    -smp 4 \
    -no-reboot \
    -netdev user,id=vmnic -device e1000,netdev=vmnic,romfile= \
    $IMAGE_DISK \
    -nographic \
    -monitor none \
    -kernel ${KERNEL_BIN} \
    -initrd ${INITRD_BIN} \
    -append "${GUEST_KERNEL_APPEND}"
    $COM1_SERIAL \
    $COM2_SERIAL \
    $COM3_SERIAL \
    $COM4_SERIAL \
    $QEMU_EXIT_DEVICE \
    $QEMU_TEST_IO_DEVICE

stty intr ^C
