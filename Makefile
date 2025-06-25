FEATURES ?= vtpm
ifneq ($(FEATURES),)
SVSM_ARGS += --features ${FEATURES}
endif

FEATURES_TEST ?= vtpm,virtio-drivers
SVSM_ARGS_TEST += --no-default-features
ifneq ($(FEATURES_TEST),)
SVSM_ARGS_TEST += --features ${FEATURES_TEST}
endif

CLIPPY_OPTIONS ?=
CLIPPY_ARGS ?= -D warnings
ifdef UNSAFE_BLOCKS
CLIPPY_ARGS += -W warnings -W clippy::undocumented_unsafe_blocks
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

STAGE1_RUSTC_ARGS += -C panic=abort

STAGE1_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/stage1"
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

IGVM_FILES = bin/coconut-qemu.igvm bin/coconut-hyperv.igvm bin/coconut-vanadium.igvm
IGVMBUILDER = "target/${TARGET_PATH}/igvmbuilder"
IGVMBIN = bin/igvmbld
IGVMMEASURE = "target/${TARGET_PATH}/igvmmeasure"
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
	cargo build ${CARGO_ARGS} --package igvmbuilder

$(IGVMMEASURE):
	cargo build ${CARGO_ARGS} --package igvmmeasure

bin/coconut-qemu.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/stage1-trampoline.bin bin/svsm-kernel.elf bin/stage2.bin ${FS_BIN}
	$(IGVMBUILDER) --sort --policy 0x30000 --output $@ --tdx-stage1 bin/stage1-trampoline.bin --stage2 bin/stage2.bin --kernel bin/svsm-kernel.elf --filesystem ${FS_BIN} ${BUILD_FW} qemu --snp --tdp
	$(IGVMMEASURE) --check-kvm $@ measure

bin/coconut-hyperv.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/stage1-trampoline.bin bin/svsm-kernel.elf bin/stage2.bin
	$(IGVMBUILDER) --sort --output $@ --tdx-stage1 bin/stage1-trampoline.bin --stage2 bin/stage2.bin --kernel bin/svsm-kernel.elf --comport 3 hyper-v --snp --tdp --vsm
	$(IGVMMEASURE) $@ measure

bin/coconut-test-qemu.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/stage1-trampoline.bin bin/test-kernel.elf bin/stage2.bin
	$(IGVMBUILDER) --sort --output $@ --tdx-stage1 bin/stage1-trampoline.bin --stage2 bin/stage2.bin --kernel bin/test-kernel.elf qemu --snp --tdp
	$(IGVMMEASURE) $@ measure

bin/coconut-test-hyperv.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/stage1-trampoline.bin bin/test-kernel.elf bin/stage2.bin
	$(IGVMBUILDER) --sort --output $@ --tdx-stage1 bin/stage1-trampoline.bin --stage2 bin/stage2.bin --kernel bin/test-kernel.elf --comport 3 hyper-v --snp --tdp --vsm
	$(IGVMMEASURE) $@ measure

bin/coconut-vanadium.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/stage1-trampoline.bin bin/svsm-kernel.elf bin/stage2.bin ${FS_BIN}
	$(IGVMBUILDER) --sort --policy 0x30000 --output $@ --tdx-stage1 bin/stage1-trampoline.bin --stage2 bin/stage2.bin --kernel bin/svsm-kernel.elf --filesystem ${FS_BIN} ${BUILD_FW} vanadium --snp --tdp
	$(IGVMMEASURE) --check-kvm --native-zero $@ measure

bin/coconut-test-vanadium.igvm: $(IGVMBUILDER) $(IGVMMEASURE) bin/stage1-trampoline.bin bin/test-kernel.elf bin/stage2.bin
	$(IGVMBUILDER) --sort --output $@ --tdx-stage1 bin/stage1-trampoline.bin --stage2 bin/stage2.bin --kernel bin/test-kernel.elf vanadium --snp --tdp
	$(IGVMMEASURE) --check-kvm --native-zero $@ measure

test:
	cargo test ${CARGO_ARGS} ${SVSM_ARGS_TEST} --workspace

test-igvm: bin/coconut-test-qemu.igvm bin/coconut-test-hyperv.igvm bin/coconut-test-vanadium.igvm

test-in-svsm: utils/cbit bin/coconut-test-qemu.igvm $(IGVMMEASUREBIN)
	./scripts/test-in-svsm.sh

test-in-hyperv: bin/coconut-test-hyperv.igvm

doc:
	cargo doc --package svsm --all-features --document-private-items --target=x86_64-unknown-none --open

docsite:
	mkdir -p ${DOC_SITE}
	cargo doc --package svsm --all-features --document-private-items --target=x86_64-unknown-none --no-deps
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

bin/meta.bin: utils/gen_meta utils/print-meta bin
	./utils/gen_meta $@

bin/stage2.bin: bin
	cargo build --package svsm --bin stage2 ${CARGO_ARGS} --target=x86_64-unknown-none
	objcopy -O binary ${STAGE2_ELF} $@

bin/svsm-kernel.elf: bin
	cargo build --package svsm --bin svsm ${CARGO_ARGS} ${SVSM_ARGS} --target=x86_64-unknown-none
	objcopy -O elf64-x86-64 --strip-unneeded ${SVSM_KERNEL_ELF} $@

bin/test-kernel.elf: bin
# RUSTDOC=true removes doctests, which is necessary as they do not work with
# custom test runners. See https://github.com/coconut-svsm/svsm/issues/705.
	RUSTDOC=true LINK_TEST=1 cargo +nightly test --package svsm ${CARGO_ARGS} ${SVSM_ARGS_TEST} \
		--target=x86_64-unknown-none \
		--config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ../${TEST_KERNEL_ELF}"]'
	objcopy -O elf64-x86-64 --strip-unneeded ${TEST_KERNEL_ELF} bin/test-kernel.elf

${FS_BIN}: bin
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) ${FS_BIN}
endif
	touch ${FS_BIN}

stage1_elf_full: bin/stage2.bin bin/svsm-fs.bin bin/svsm-kernel.elf bin/meta.bin
	ln -sf svsm-kernel.elf bin/kernel.elf
	cargo rustc --manifest-path stage1/Cargo.toml ${CARGO_ARGS} --target=x86_64-unknown-none --features load-stage2 --bin stage1 -- ${STAGE1_RUSTC_ARGS}
	rm -f bin/kernel.elf

stage1_elf_trampoline: bin/meta.bin
	cargo rustc --manifest-path stage1/Cargo.toml ${CARGO_ARGS} --target=x86_64-unknown-none --bin stage1 -- ${STAGE1_RUSTC_ARGS}

stage1_elf_test: bin/stage2.bin bin/svsm-fs.bin bin/test-kernel.elf bin/meta.bin
	ln -sf test-kernel.elf bin/kernel.elf
	cargo rustc --manifest-path stage1/Cargo.toml ${CARGO_ARGS} --target=x86_64-unknown-none --features load-stage2 --bin stage1 -- ${STAGE1_RUSTC_ARGS}
	rm -f bin/kernel.elf

bin/svsm: stage1_elf_full
	cp -f $(STAGE1_ELF) $@

bin/stage1-trampoline: stage1_elf_trampoline
	cp -f $(STAGE1_ELF) $@

bin/svsm-test: stage1_elf_test
	cp -f $(STAGE1_ELF) $@

bin/svsm.bin: bin/svsm
	objcopy -O binary $< $@

bin/stage1-trampoline.bin: bin/stage1-trampoline
	objcopy -O binary $< $@

bin/svsm-test.bin: bin/svsm-test
	objcopy -O binary $< $@

clippy:
	cargo clippy ${CLIPPY_OPTIONS} --all-features --workspace --exclude svsm --exclude stage1 --exclude svsm-fuzz -- ${CLIPPY_ARGS}
	RUSTFLAGS="--cfg fuzzing" cargo clippy ${CLIPPY_OPTIONS} --all-features --package svsm-fuzz -- ${CLIPPY_ARGS}
	cargo clippy ${CLIPPY_OPTIONS} --all-features --package svsm --target x86_64-unknown-none -- ${CLIPPY_ARGS}
	cargo clippy ${CLIPPY_OPTIONS} --all-features --package stage1 --target x86_64-unknown-none -- ${CLIPPY_ARGS} ${STAGE1_RUSTC_ARGS}
	cargo clippy ${CLIPPY_OPTIONS} --all-features --workspace --tests --exclude packit -- ${CLIPPY_ARGS}

clean:
	cargo clean
	rm -f stage1/*.o stage1/*.bin stage1/*.elf
	rm -f utils/gen_meta utils/print-meta
	rm -rf bin

distclean: clean
	$(MAKE) -C libtcgtpm $@

.PHONY: test clean clippy bin/stage2.bin bin/svsm-kernel.elf bin/test-kernel.elf stage1_elf_full stage1_elf_trampoline stage1_elf_test distclean
