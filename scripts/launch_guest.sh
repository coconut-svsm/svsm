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

# `reduced-phys-bits` is used to provide the number of bits we loose in
# physical address space. On EPYC, a guest will lose a maximum of 1 bit,
# so using a value other than 1 is only reducing physical addressing range
# in the guest.
REDUCED_PHYS_BITS=1
C_BIT_POS=$(cargo run --package cbit || true)
COM1_SERIAL="-serial stdio" # console
COM2_SERIAL="-serial null"  # debug
COM3_SERIAL="-serial null"  # used by hyper-v
COM4_SERIAL="-serial null"  # used by in-SVSM tests
QEMU_EXIT_DEVICE=""
QEMU_TEST_IO_DEVICE=""
QEMU_NETDEV="-netdev user,id=vmnic -device e1000,netdev=vmnic,romfile="
CGS=sev
CPU=EPYC-v4
ACCEL=kvm
IGVM_OBJ=""
SNAPSHOT="on"

STATE_DEVICE=""
VSOCK_DEVICE=""
VIRTIO=0

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
    --state)
      VIRTIO=1
      STATE_DEVICE+="-drive file=$2,format=raw,if=none,id=svsm_storage,cache=none "
      STATE_DEVICE+="-device virtio-blk-device,drive=svsm_storage "
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
    --nocc)
      CGS=nocc
      shift
      ;;
    --aproxy)
      COM3_SERIAL="-serial unix:$2"
      shift
      shift
      ;;
    --no-netdev)
      QEMU_NETDEV=""
      shift
      ;;
    --snapshot)
      SNAPSHOT=$2
      shift
      shift
      ;;
    --vsock)
      VIRTIO=1
      VSOCK_DEVICE="-device vhost-vsock-device,guest-cid=$2 "
      shift
      shift
      ;;
    --)
      shift
      break
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

VIRTIO_ENABLE=""
VIRTIO_CONFIG=""
if [ "$VIRTIO" -eq 1 ]; then
  VIRTIO_ENABLE="x-svsm-virtio-mmio=on"
  VIRTIO_CONFIG="-global virtio-mmio.force-legacy=false "
fi

# Split the QEMU version number so we can specify the correct parameters
QEMU_VERSION=$($QEMU --version | grep -Po '(?<=version )[^ ]+')
QEMU_MAJOR=${QEMU_VERSION%%.*}
QEMU_BUILD=${QEMU_VERSION##*.}
QEMU_MINOR=${QEMU_VERSION##"$QEMU_MAJOR".}
QEMU_MINOR=${QEMU_MINOR%%."$QEMU_BUILD"}

if (( QEMU_MAJOR < 10 || (QEMU_MAJOR == 10 && QEMU_MINOR < 1) )); then
  echo "Error: SVSM requires QEMU 10.1 or newer (with patches)." >&2
  exit 1
fi

case "$CGS" in
  nocc)
    SNP_GUEST="-object nocc,id=cgs0"
    CPU=max,smep=on
    ACCEL=tcg
    ;;
  sev)
    SNP_GUEST="-object sev-snp-guest,id=cgs0,cbitpos=$C_BIT_POS,reduced-phys-bits=$REDUCED_PHYS_BITS"
    ;;
  *)
    echo "Error: Unexpected CGS value '$CGS'"
    exit 1
esac
MACHINE=q35,confidential-guest-support=cgs0,memory-backend=mem0,igvm-cfg=igvm0,accel=$ACCEL
MEMORY=memory-backend-memfd,size=8G,id=mem0,share=true,prealloc=false,reserve=false
IGVM_OBJ="-object igvm-cfg,id=igvm0,file=$IGVM"

# Setup a disk if an image has been specified
if [ ! -z "$IMAGE" ]; then
  IMAGE_DISK="-drive file=$IMAGE,if=none,id=disk0,format=qcow2,snapshot=$SNAPSHOT \
    -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=on \
    -device scsi-hd,drive=disk0"
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


# Remap Ctrl-C to Ctrl-] to allow the guest to handle Ctrl-C,
# if we are running with a TTY attached.
if [ -t 0 ]; then
  echo "Press Ctrl-] to interrupt"
  echo "============================="
  # Store original terminal settings and restore it on exit
  STTY_ORIGINAL=$(stty -g)
  trap 'stty "$STTY_ORIGINAL"' EXIT

  stty intr ^]
fi

# Temporarily use -vga none to avoid IGVM VGA init failure in QEMU 10.1
$SUDO_CMD \
  "$QEMU" \
    -cpu $CPU \
    -machine $MACHINE,$VIRTIO_ENABLE \
    -object $MEMORY \
    $IGVM_OBJ \
    $SNP_GUEST \
    -smp 4 \
    -no-reboot \
    $QEMU_NETDEV \
    $IMAGE_DISK \
    -nographic \
    -vga none \
    -monitor none \
    $COM1_SERIAL \
    $COM2_SERIAL \
    $COM3_SERIAL \
    $COM4_SERIAL \
    $QEMU_EXIT_DEVICE \
    $QEMU_TEST_IO_DEVICE \
    $VIRTIO_CONFIG \
    $STATE_DEVICE \
    $VSOCK_DEVICE \
    "$@"
