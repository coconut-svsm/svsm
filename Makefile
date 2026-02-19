FEATURES ?= vtpm
ifneq ($(FEATURES),)
SVSM_ARGS += --features ${FEATURES}
XBUILD_ARGS += -f ${FEATURES}
endif

FEATURES_TEST ?= vtpm,virtio-drivers,block,vsock
SVSM_ARGS_TEST += --no-default-features
ifneq ($(FEATURES_TEST),)
SVSM_ARGS_TEST += --features ${FEATURES_TEST}
XBUILD_ARGS_TEST += --feature ${FEATURES_TEST}
endif

TEST_ARGS ?=

CLIPPY_OPTIONS ?=
CLIPPY_ARGS ?= -D warnings

ifdef RELEASE
TARGET_PATH=release
CARGO_ARGS += --release
XBUILD_ARGS += --release
OBJCOPY_ELF_ARGS := --strip-unneeded
else
TARGET_PATH=debug
OBJCOPY_ELF_ARGS := --strip-debug
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

IGVM_FILES = bin/coconut-qemu.igvm bin/coconut-hyperv.igvm bin/coconut-vanadium.igvm
IGVM_TEST_FILES = bin/coconut-test-qemu.igvm bin/coconut-test-hyperv.igvm bin/coconut-test-vanadium.igvm
IGVMBUILDER = "target/${TARGET_PATH}/igvmbuilder"
IGVMBIN = bin/igvmbld
IGVMMEASURE = "target/${TARGET_PATH}/igvmmeasure"
IGVMMEASUREBIN = bin/igvmmeasure

APROXY = "target/x86_64-unknown-linux-gnu/${TARGET_PATH}/aproxy"
APROXYBIN = bin/aproxy

RUSTDOC_OUTPUT = target/x86_64-unknown-none/doc
DOC_SITE = target/x86_64-unknown-none/site

all: igvm

aproxy: $(APROXY) $(APROXYBIN)

igvm: $(IGVM_FILES) $(IGVMBIN) $(IGVMMEASUREBIN)

bin:
	mkdir -v -p bin

$(APROXYBIN): $(APROXY) bin
	cp -f $(APROXY) $@

$(APROXY):
	cargo build ${CARGO_ARGS} --target=x86_64-unknown-linux-gnu -p aproxy

$(IGVMBIN): $(IGVMBUILDER) bin
	cp -f $(IGVMBUILDER) $@

$(IGVMMEASUREBIN): $(IGVMMEASURE) bin
	cp -f $(IGVMMEASURE) $@

$(IGVMBUILDER):
	cargo build ${CARGO_ARGS} --package igvmbuilder

$(IGVMMEASURE):
	cargo build ${CARGO_ARGS} --package igvmmeasure

bin/coconut-qemu.igvm:
	cargo xbuild $(XBUILD_ARGS) ./configs/qemu-target.json

bin/coconut-hyperv.igvm:
	cargo xbuild $(XBUILD_ARGS) ./configs/hyperv-target.json

bin/coconut-vanadium.igvm:
	cargo xbuild $(XBUILD_ARGS) ./configs/vanadium-target.json

bin/coconut-test-qemu.igvm:
	cargo xbuild $(XBUILD_ARGS_TEST) ./configs/test/qemu-test-target.json

bin/coconut-test-hyperv.igvm:
	cargo xbuild $(XBUILD_ARGS_TEST) ./configs/test/hyperv-test-target.json

bin/coconut-test-vanadium.igvm:
	cargo xbuild $(XBUILD_ARGS_TEST) ./configs/test/vanadium-test-target.json

test:
	cargo test ${CARGO_ARGS} ${SVSM_ARGS_TEST} --workspace

test-igvm: $(IGVM_TEST_FILES)

test-in-svsm: bin/coconut-test-qemu.igvm $(IGVMMEASUREBIN)
	./scripts/test-in-svsm.sh $(TEST_ARGS)

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

bin/gen_meta: tools/gen_meta.c bin
	cc -O3 -Wall -o $@ $<

bin/print-meta: tools/print-meta.c bin
	cc -O3 -Wall -o $@ $<

bin/meta.bin: bin/gen_meta bin/print-meta bin
	./bin/gen_meta $@

bin/stage2.bin: bin
	cargo build --package svsm --bin stage2 ${CARGO_ARGS} --target=x86_64-unknown-none
	objcopy -O binary ${STAGE2_ELF} $@

bin/svsm-kernel.elf: bin
	cargo build --package svsm --bin svsm ${CARGO_ARGS} ${SVSM_ARGS} --target=x86_64-unknown-none
	objcopy -O elf64-x86-64 ${OBJCOPY_ELF_ARGS} ${SVSM_KERNEL_ELF} $@

bin/test-kernel.elf: bin
# RUSTDOC=true removes doctests, which is necessary as they do not work with
# custom test runners. See https://github.com/coconut-svsm/svsm/issues/705.
	RUSTDOC=true LINK_TEST=1 cargo +nightly test --package svsm ${CARGO_ARGS} ${SVSM_ARGS_TEST} \
		--target=x86_64-unknown-none \
		--config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ../$@"]'

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
	rm -rf bin
	rm -f release/src/git_version.rs

distclean: clean

.PHONY: test clean clippy bin/stage2.bin bin/svsm-kernel.elf bin/test-kernel.elf stage1_elf_full stage1_elf_trampoline stage1_elf_test distclean $(APROXYBIN) $(IGVM_FILES) $(IGVM_TEST_FILES)
