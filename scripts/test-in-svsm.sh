#!/bin/bash
#

set -e

if [ "$QEMU" == "" ]; then
	echo "Set QEMU environment variable to QEMU installation path" && exit 1
fi
if [ "$OVMF_PATH" == "" ]; then
	echo "Set OVMF_PATH environment variable to a folder containing OVMF_CODE.fd and OVMF_VARS.fd" && exit 1
fi
if [ "$SUDO" != "" ]; then
	SUDO_CMD="sudo"
else
	SUDO_CMD=""
fi

C_BIT_POS=`utils/cbit`

$SUDO_CMD $QEMU \
	-enable-kvm \
	-cpu EPYC-v4 \
	-machine q35,confidential-guest-support=sev0,memory-backend=ram1,kvm-type=protected \
	-object memory-backend-memfd-private,id=ram1,size=1G,share=true \
	-object sev-snp-guest,id=sev0,cbitpos=$C_BIT_POS,reduced-phys-bits=1,svsm=on \
	-smp 8 \
	-no-reboot \
	-drive if=pflash,format=raw,unit=0,file=$OVMF_PATH/OVMF_CODE.fd,readonly=on \
	-drive if=pflash,format=raw,unit=1,file=$OVMF_PATH/OVMF_VARS.fd,snapshot=on \
	-drive if=pflash,format=raw,unit=2,file=./svsm.bin,readonly=on \
	-nographic \
	-monitor none \
	-serial stdio \
	-device isa-debug-exit,iobase=0xf4,iosize=0x04 || true
