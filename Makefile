FEATURES ?= "default"
CARGO_ARGS = --features ${FEATURES}

ifdef RELEASE
TARGET_PATH=release
CARGO_ARGS += --release
else
TARGET_PATH=debug
endif

STAGE2_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/stage2"
KERNEL_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/svsm"
TEST_KERNEL_ELF = target/x86_64-unknown-none/${TARGET_PATH}/svsm-test
FS_FILE ?= none

C_BIT_POS ?= 51

STAGE1_OBJS = stage1/stage1.o stage1/reset.o

all: stage1/kernel.elf svsm.bin

test:
	cargo test --target=x86_64-unknown-linux-gnu

test-in-svsm: stage1/test-kernel.elf svsm.bin
ifndef QEMU
	echo "Set QEMU environment variable to QEMU installation path" && exit 1
endif
ifndef OVMF
	echo "Set OVMFenvironment variable to a folder containing OVMF_CODE.fd and OVMF_VARS.fd" && exit 1
endif
	$(QEMU)/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35,confidential-guest-support=sev0,memory-backend=ram1,kvm-type=protected \
		-object memory-backend-memfd-private,id=ram1,size=1G,share=true \
		-object sev-snp-guest,id=sev0,cbitpos=$(C_BIT_POS),reduced-phys-bits=1,svsm=on \
		-smp 8 \
		-no-reboot \
		-drive if=pflash,format=raw,unit=0,file=$(OVMF)/OVMF_CODE.fd,readonly=on \
		-drive if=pflash,format=raw,unit=1,file=$(OVMF)/OVMF_VARS.fd,snapshot=on \
		-drive if=pflash,format=raw,unit=2,file=./svsm.bin,readonly=on \
		-nographic \
		-monitor none \
		-serial stdio \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 || true

utils/gen_meta: utils/gen_meta.c
	cc -O3 -Wall -o $@ $<

utils/print-meta: utils/print-meta.c
	cc -O3 -Wall -o $@ $<

utils/cbit: utils/cbit.c
	cc -O3 -Wall -o $@ $<

stage1/meta.bin: utils/gen_meta utils/print-meta
	./utils/gen_meta $@

stage1/stage2.bin:
	cargo build ${CARGO_ARGS} --bin stage2
	objcopy -O binary ${STAGE2_ELF} $@

stage1/kernel.elf:
	cargo build ${CARGO_ARGS} --bin svsm
	objcopy -O elf64-x86-64 --strip-unneeded ${KERNEL_ELF} $@

stage1/test-kernel.elf:
	LINK_TEST=1 cargo +nightly test --config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ${TEST_KERNEL_ELF}"]'
	objcopy -O elf64-x86-64 --strip-unneeded ${TEST_KERNEL_ELF} stage1/kernel.elf

stage1/svsm-fs.bin:
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) stage1/svsm-fs.bin
endif
	touch stage1/svsm-fs.bin

stage1/stage1.o: stage1/stage1.S stage1/stage2.bin stage1/svsm-fs.bin
	cc -c -o $@ stage1/stage1.S

stage1/reset.o:  stage1/reset.S stage1/meta.bin

stage1/stage1: ${STAGE1_OBJS}
	$(CC) -o $@ $(STAGE1_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds

svsm.bin: stage1/stage1
	objcopy -O binary $< $@

clean:
	cargo clean
	rm -f stage1/stage2.bin svsm.bin stage1/meta.bin stage1/kernel.elf stage1/stage1 stage1/svsm-fs.bin ${STAGE1_OBJS} utils/gen_meta utils/print-meta

.PHONY: stage1/stage2.bin stage1/kernel.elf stage1/test-kernel.elf svsm.bin clean stage1/svsm-fs.bin test test-in-svsm
