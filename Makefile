FEATURES ?= "default"
CARGO_ARGS = --features ${FEATURES}

ifdef RELEASE
TARGET_PATH="release"
CARGO_ARGS += --release
else
TARGET_PATH="debug"
endif

STAGE2_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/stage2"
KERNEL_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/svsm"
FS_FILE ?= none

STAGE1_OBJS = stage1/stage1.o stage1/reset.o

all: svsm.bin

test:
	cargo test --target=x86_64-unknown-linux-gnu

utils/gen_meta: utils/gen_meta.c
	cc -O3 -Wall -o $@ $<

utils/print-meta: utils/print-meta.c
	cc -O3 -Wall -o $@ $<

stage1/meta.bin: utils/gen_meta utils/print-meta
	./utils/gen_meta $@

stage1/stage2.bin:
	cargo build ${CARGO_ARGS} --bin stage2
	objcopy -O binary ${STAGE2_ELF} $@

stage1/kernel.elf:
	cargo build ${CARGO_ARGS} --bin svsm
	objcopy -O elf64-x86-64 --strip-unneeded ${KERNEL_ELF} $@

stage1/svsm-fs.bin:
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) stage1/svsm-fs.bin
endif
	touch stage1/svsm-fs.bin

stage1/stage1.o: stage1/stage1.S stage1/stage2.bin stage1/kernel.elf stage1/svsm-fs.bin
	cc -c -o $@ stage1/stage1.S

stage1/reset.o:  stage1/reset.S stage1/meta.bin

stage1/stage1: ${STAGE1_OBJS}
	$(CC) -o $@ $(STAGE1_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds

svsm.bin: stage1/stage1
	objcopy -O binary $< $@

clean:
	cargo clean
	rm -f stage1/stage2.bin svsm.bin stage1/meta.bin stage1/kernel.elf stage1/stage1 stage1/svsm-fs.bin ${STAGE1_OBJS} utils/gen_meta utils/print-meta

.PHONY: stage1/stage2.bin stage1/kernel.elf svsm.bin clean stage1/svsm-fs.bin test
