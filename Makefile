FEATURES ?= "default"
SVSM_ARGS = --features ${FEATURES}

ifdef RELEASE
TARGET_PATH=release
CARGO_ARGS += --release
else
TARGET_PATH=debug
endif

ifdef OFFLINE
CARGO_ARGS += --locked --offline
endif

ifeq ($(V), 1)
CARGO_ARGS += -v
else ifeq ($(V), 2)
CARGO_ARGS += -vv
endif

STAGE2_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/stage2"
SVSM_KERNEL_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/svsm"
TEST_KERNEL_ELF = target/x86_64-unknown-none/${TARGET_PATH}/svsm-test
FS_FILE ?= none

FW_FILE ?= none
ifneq ($(FW_FILE), none)
BUILD_FW = --firmware ${FW_FILE}
else
BUILD_FW =
endif

C_BIT_POS ?= 51

STAGE1_OBJS = stage1/stage1.o stage1/reset.o
STAGE1_TEST_OBJS = stage1/stage1-test.o stage1/reset.o
IGVM_FILES = bin/coconut-qemu.igvm bin/coconut-hyperv.igvm
IGVMBUILDER = "target/x86_64-unknown-linux-gnu/${TARGET_PATH}/igvmbuilder"
IGVMBIN = bin/igvmbld

all: svsm.bin igvm

igvm: $(IGVM_FILES) $(IGVMBIN)

$(IGVMBIN): $(IGVMBUILDER)
	mkdir -v -p bin
	cp -f $(IGVMBUILDER) $@

$(IGVMBUILDER):
	cargo build ${CARGO_ARGS} --target=x86_64-unknown-linux-gnu -p igvmbuilder

bin/coconut-qemu.igvm: $(IGVMBUILDER) stage1/svsm-kernel.elf stage1/stage2.bin
	mkdir -v -p bin
	$(IGVMBUILDER) --sort --output $@ --stage2 stage1/stage2.bin --kernel stage1/svsm-kernel.elf ${BUILD_FW} qemu

bin/coconut-hyperv.igvm: $(IGVMBUILDER) stage1/svsm-kernel.elf stage1/stage2.bin
	mkdir -v -p bin
	$(IGVMBUILDER) --sort --output $@ --stage2 stage1/stage2.bin --kernel stage1/svsm-kernel.elf --comport 3 hyper-v

test:
	cargo test --workspace --target=x86_64-unknown-linux-gnu

test-in-svsm: utils/cbit svsm-test.bin
	./scripts/test-in-svsm.sh

doc:
	cargo doc -p svsm --open --all-features --document-private-items

utils/gen_meta: utils/gen_meta.c
	cc -O3 -Wall -o $@ $<

utils/print-meta: utils/print-meta.c
	cc -O3 -Wall -o $@ $<

utils/cbit: utils/cbit.c
	cc -O3 -Wall -o $@ $<

stage1/meta.bin: utils/gen_meta utils/print-meta
	./utils/gen_meta $@

stage1/stage2.bin:
	cargo build ${CARGO_ARGS} ${SVSM_ARGS} --bin stage2
	objcopy -O binary ${STAGE2_ELF} $@

stage1/svsm-kernel.elf:
	cargo build ${CARGO_ARGS} ${SVSM_ARGS} --bin svsm
	objcopy -O elf64-x86-64 --strip-unneeded ${SVSM_KERNEL_ELF} $@

stage1/test-kernel.elf:
	LINK_TEST=1 cargo +nightly test -p svsm --config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ../${TEST_KERNEL_ELF}"]'
	objcopy -O elf64-x86-64 --strip-unneeded ${TEST_KERNEL_ELF} stage1/test-kernel.elf

stage1/svsm-fs.bin:
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) stage1/svsm-fs.bin
endif
	touch stage1/svsm-fs.bin

stage1/stage1.o: stage1/stage1.S stage1/stage2.bin stage1/svsm-fs.bin stage1/svsm-kernel.elf
	ln -sf svsm-kernel.elf stage1/kernel.elf
	cc -c -o $@ stage1/stage1.S
	rm -f stage1/kernel.elf

stage1/stage1-test.o: stage1/stage1.S stage1/stage2.bin stage1/svsm-fs.bin stage1/test-kernel.elf
	ln -sf test-kernel.elf stage1/kernel.elf
	cc -c -o $@ stage1/stage1.S
	rm -f stage1/kernel.elf

stage1/reset.o:  stage1/reset.S stage1/meta.bin

stage1/stage1: ${STAGE1_OBJS}
	$(CC) -o $@ $(STAGE1_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds -no-pie

stage1/stage1-test: ${STAGE1_TEST_OBJS}
	$(CC) -o $@ $(STAGE1_TEST_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds -no-pie

svsm.bin: stage1/stage1
	objcopy -O binary $< $@

svsm-test.bin: stage1/stage1-test
	objcopy -O binary $< $@

clippy:
	cargo clippy --workspace --exclude igvmbuilder --exclude svsm-fuzz --all-features -- -D warnings
	cargo clippy --workspace --all-features --exclude svsm --target=x86_64-unknown-linux-gnu -- -D warnings

clean:
	cargo clean
	rm -f stage1/stage2.bin svsm.bin stage1/meta.bin stage1/kernel.elf stage1/stage1 stage1/svsm-fs.bin ${STAGE1_OBJS} utils/gen_meta utils/print-meta
	rm -rf bin

.PHONY: test clean stage1/stage2.bin stage1/svsm-kernel.elf stage1/test-kernel.elf

