FEATURES ?= "default"
SVSM_ARGS = --features ${FEATURES}

SVSM_ARGS_TEST = --no-default-features
ifdef FEATURES_TEST
	SVSM_ARGS_TEST += --features ${FEATURES_TEST}
endif

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
FS_BIN=bin/svsm-fs.bin
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
IGVMMEASURE = "target/x86_64-unknown-linux-gnu/${TARGET_PATH}/igvmmeasure"
IGVMMEASUREBIN = bin/igvmmeasure

RUSTDOC_OUTPUT = target/x86_64-unknown-none/doc
DOC_SITE = target/x86_64-unknown-none/site

all: bin/svsm.bin igvm

igvm: $(IGVM_FILES) $(IGVMBIN) $(IGVMMEASUREBIN)

bin:
	mkdir -v -p bin

$(IGVMBIN): $(IGVMBUILDER) bin
	cp -f $(IGVMBUILDER) $@

$(IGVMMEASUREBIN): $(IGVMMEASURE) bin
	cp -f $(IGVMMEASURE) $@

$(IGVMBUILDER):
	cargo build ${CARGO_ARGS} --target=x86_64-unknown-linux-gnu -p igvmbuilder

$(IGVMMEASURE):
	cargo build ${CARGO_ARGS} --target=x86_64-unknown-linux-gnu -p igvmmeasure

bin/coconut-qemu.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/svsm-kernel.elf bin/stage2.bin ${FS_BIN}
	$(IGVMBUILDER) --sort --policy 0x30000 --output $@ --stage2 bin/stage2.bin --kernel bin/svsm-kernel.elf --filesystem ${FS_BIN} ${BUILD_FW} qemu --snp
	$(IGVMMEASURE) --check-kvm $@ measure

bin/coconut-hyperv.igvm: $(IGVMBUILDER)  $(IGVMMEASURE) bin/svsm-kernel.elf bin/stage2.bin
	$(IGVMBUILDER) --sort --output $@ --stage2 bin/stage2.bin --kernel bin/svsm-kernel.elf --comport 3 hyper-v --native --snp
	$(IGVMMEASURE) $@ measure

bin/coconut-test-qemu.igvm: $(IGVMBUILDER)  $(IGVMMEASURE) bin/test-kernel.elf bin/stage2.bin
	$(IGVMBUILDER) --sort --output $@ --stage2 bin/stage2.bin --kernel bin/test-kernel.elf qemu --snp
	$(IGVMMEASURE) $@ measure

test:
	cargo test ${CARGO_ARGS} ${SVSM_ARGS_TEST} --workspace --target=x86_64-unknown-linux-gnu

test-in-svsm: utils/cbit bin/coconut-test-qemu.igvm
	./scripts/test-in-svsm.sh

doc:
	cargo doc -p svsm --open --all-features --document-private-items

docsite:
	mkdir -p ${DOC_SITE}
	cargo doc -p svsm --all-features --document-private-items --no-deps
	mkdocs build -f Documentation/mkdocs.yml -d ../${DOC_SITE}
	cp -r ${RUSTDOC_OUTPUT} ${DOC_SITE}/rustdoc

docsite-serve:
	mkdocs serve -f Documentation/mkdocs.yml

utils/gen_meta: utils/gen_meta.c
	cc -O3 -Wall -o $@ $<

utils/print-meta: utils/print-meta.c
	cc -O3 -Wall -o $@ $<

utils/cbit: utils/cbit.c
	cc -O3 -Wall -o $@ $<

bin/meta.bin: utils/gen_meta utils/print-meta
	./utils/gen_meta $@

bin/stage2.bin: bin
	cargo build --manifest-path kernel/Cargo.toml ${CARGO_ARGS} --no-default-features --bin stage2
	objcopy -O binary ${STAGE2_ELF} $@

bin/svsm-kernel.elf: bin
	cargo build ${CARGO_ARGS} ${SVSM_ARGS} --bin svsm
	objcopy -O elf64-x86-64 --strip-unneeded ${SVSM_KERNEL_ELF} $@

bin/test-kernel.elf: bin
	LINK_TEST=1 cargo +nightly test ${CARGO_ARGS} -p svsm --config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ../${TEST_KERNEL_ELF}"]'
	objcopy -O elf64-x86-64 --strip-unneeded ${TEST_KERNEL_ELF} bin/test-kernel.elf

${FS_BIN}: bin
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) ${FS_BIN}
endif
	touch ${FS_BIN}

stage1/stage1.o: stage1/stage1.S bin/stage2.bin bin/svsm-fs.bin bin/svsm-kernel.elf bin
	ln -sf svsm-kernel.elf bin/kernel.elf
	cc -c -o $@ stage1/stage1.S
	rm -f bin/kernel.elf

stage1/stage1-test.o: stage1/stage1.S bin/stage2.bin bin/svsm-fs.bin bin/test-kernel.elf bin
	ln -sf test-kernel.elf bin/kernel.elf
	cc -c -o $@ stage1/stage1.S
	rm -f bin/kernel.elf

stage1/reset.o:  stage1/reset.S bin/meta.bin

bin/stage1: ${STAGE1_OBJS}
	$(CC) -o $@ $(STAGE1_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds -no-pie

bin/stage1-test: ${STAGE1_TEST_OBJS}
	$(CC) -o $@ $(STAGE1_TEST_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds -no-pie

bin/svsm.bin: bin/stage1
	objcopy -O binary $< $@

clippy:
	cargo clippy --workspace --all-features --exclude svsm-fuzz --exclude igvmbuilder --exclude igvmmeasure -- -D warnings
	cargo clippy --workspace --all-features --exclude svsm-fuzz --exclude svsm --target=x86_64-unknown-linux-gnu -- -D warnings
	RUSTFLAGS="--cfg fuzzing" cargo clippy --package svsm-fuzz --all-features --target=x86_64-unknown-linux-gnu -- -D warnings
	cargo clippy --workspace --all-features --tests --target=x86_64-unknown-linux-gnu -- -D warnings

clean:
	cargo clean
	rm -f stage1/*.o stage1/*.bin stage1/*.elf
	rm -f ${STAGE1_OBJS} utils/gen_meta utils/print-meta
	rm -rf bin

distclean: clean
	$(MAKE) -C libmstpm $@

.PHONY: test clean clippy bin/stage2.bin bin/svsm-kernel.elf bin/test-kernel.elf distclean
