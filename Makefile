FEATURES ?= vtpm
ifneq ($(FEATURES),)
SVSM_ARGS += --features ${FEATURES}
XBUILD_ARGS += -f ${FEATURES}
endif

FEATURES_TEST ?= vtpm,virtio-drivers,block,vsock,uefivars,secureboot
SVSM_ARGS_TEST += --no-default-features
ifneq ($(FEATURES_TEST),)
SVSM_ARGS_TEST += --features ${FEATURES_TEST}
XBUILD_ARGS_TEST += --feature ${FEATURES_TEST}
endif

TEST_ARGS ?=

CARGO ?= cargo
CLIPPY_OPTIONS ?= --all-features
CLIPPY_ARGS ?= -D warnings

ifdef CARGO_HACK
CARGO = cargo hack
CLIPPY_OPTIONS = --each-feature
endif

ifdef RELEASE
TARGET_PATH=release
CARGO_ARGS += --release
XBUILD_ARGS += --release
XBUILD_ARGS_TEST += --release
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

BLDR_ELF = "target/x86_64-unknown-none/$(TARGET_PATH)/bldr"
SVSM_KERNEL_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/svsm"
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
	cargo test ${CARGO_ARGS} ${SVSM_ARGS_TEST} --package svsm
	cargo test ${CARGO_ARGS} --workspace --exclude svsm

miri:
	MIRIFLAGS=-Zmiri-permissive-provenance \
		cargo +nightly miri test ${CARGO_ARGS} ${SVSM_ARGS_TEST} --package svsm
	MIRIFLAGS=-Zmiri-permissive-provenance \
		cargo +nightly miri test ${CARGO_ARGS} --workspace --exclude svsm

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

bin/bldr.bin: bin
	cargo build --package bldr $(CARGO_ARGS) --target=x86_64-unknown-none
	objcopy -O binary $(BLDR_ELF) $@

bin/svsm-kernel.elf: bin
	cargo build --package svsm --bin svsm ${CARGO_ARGS} ${SVSM_ARGS} --target=x86_64-unknown-none
	objcopy -O elf64-x86-64 ${OBJCOPY_ELF_ARGS} ${SVSM_KERNEL_ELF} $@

${FS_BIN}: bin
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) ${FS_BIN}
endif
	touch ${FS_BIN}

clippy:
	${CARGO} clippy ${CLIPPY_OPTIONS} --workspace --exclude svsm --exclude stage1 --exclude svsm-fuzz --exclude uapi_tester -- ${CLIPPY_ARGS}
	RUSTFLAGS="--cfg fuzzing" ${CARGO} clippy ${CLIPPY_OPTIONS} --package svsm-fuzz -- ${CLIPPY_ARGS}
	${CARGO} clippy ${CLIPPY_OPTIONS} --package svsm --target x86_64-unknown-none -- ${CLIPPY_ARGS}
	${CARGO} clippy ${CLIPPY_OPTIONS} --package bldr --target x86_64-unknown-none -- ${CLIPPY_ARGS}
	${CARGO} clippy ${CLIPPY_OPTIONS} --package stage1 --target x86_64-unknown-none -- ${CLIPPY_ARGS}
	${CARGO} clippy ${CLIPPY_OPTIONS} --workspace --tests --exclude svsm -- ${CLIPPY_ARGS}
	${CARGO} clippy ${CLIPPY_OPTIONS} --package svsm --tests -- ${CLIPPY_ARGS}

clean:
	cargo clean
	rm -rf bin
	rm -f release/src/git_version.rs

distclean: clean

.PHONY: test miri clean clippy bin/bldr.bin bin/svsm-kernel.elf distclean $(APROXYBIN) $(IGVM_FILES) $(IGVM_TEST_FILES)
