ifeq ($(shell uname -m),x86_64)
CROSS_PREFIX :=
else
CROSS_PREFIX := x86_64-linux-gnu-
endif
CC := $(CROSS_PREFIX)gcc

ifdef RELEASE
OPENSSL_CONFIG_TYPE = --release
TCGTPM_CFLAGS = -O3 -DDEBUG=NO
else
OPENSSL_CONFIG_TYPE = --debug
TCGTPM_CFLAGS = -g -O0 -DDEBUG=YES
endif

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DEPS_DIR := $(ROOT_DIR)/deps
OUT_DIR ?= $(ROOT_DIR)
# Ensure OUT_DIR is an absolute path because we use it to build include paths
# used by different projects
override OUT_DIR := $(abspath $(OUT_DIR))

# Include CARGO_MAKEFLAGS for jobserver coordination if available
# Otherwise use -j with NUM_JOBS
ifneq ($(CARGO_MAKEFLAGS),)
MAKEFLAGS += $(CARGO_MAKEFLAGS)
else
# Use NUM_JOBS from Cargo build script environment, fallback to nproc
NUM_JOBS ?= $(shell nproc)
MAKEFLAGS += -j$(NUM_JOBS)
endif

LIBCRT_SRC_DIR = $(DEPS_DIR)/libcrt
OPENSSL_SRC_DIR = $(DEPS_DIR)/openssl
TCGTPM_SRC_DIR = $(DEPS_DIR)/tpm-20-ref/TPMCmd

LIBCRT_BUILD_DIR = $(OUT_DIR)/libcrt-build
OPENSSL_BUILD_DIR = $(OUT_DIR)/openssl-build
TCGTPM_BUILD_DIR = $(OUT_DIR)/tcgtpm-build

LIBCRT = $(LIBCRT_BUILD_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_BUILD_DIR)/libcrypto.a

LIBTPM_TARGET = Tpm_CoreLib
LIBTPM = $(TCGTPM_BUILD_DIR)/tpm/src/lib$(LIBTPM_TARGET).a

LIBPLATFORM_TARGET = Tpm_PlatformLib
LIBPLATFORM = $(TCGTPM_BUILD_DIR)/Platform/lib$(LIBPLATFORM_TARGET).a

LIBTPMBIGNUM_TARGET = Tpm_CryptoLib_TpmBigNum
LIBTPMBIGNUM = $(TCGTPM_BUILD_DIR)/tpm/cryptolibs/TpmBigNum/lib$(LIBTPMBIGNUM_TARGET).a

LIBBNMATH_TARGET = Tpm_CryptoLib_Math_Ossl
LIBBNMATH = $(TCGTPM_BUILD_DIR)/cryptolib_Ossl/lib$(LIBBNMATH_TARGET).a

OPENSSL_MAKEFILE = $(OPENSSL_BUILD_DIR)/Makefile
TCGTPM_MAKEFILE = $(TCGTPM_BUILD_DIR)/Makefile

LIBS = $(LIBCRT) $(LIBCRYPTO) $(LIBBNMATH) $(LIBTPMBIGNUM) $(LIBTPM) $(LIBPLATFORM)

# Avoid running jobs of this Makefile in parallel to avoid possible conflicts
# when building the TPM libraries, which use the same Makefile and subdirectory.
# Parallel builds are still used inside the sub-targets (-j flag)
.NOTPARALLEL:

all: $(OUT_DIR)/libtcgtpm.a

$(OUT_DIR)/libtcgtpm.a: $(LIBS)
	rm -f $@
	ar rcsTPD $@ $^

.PHONY: $(LIBCRT)

# libcrt
$(LIBCRT):
	mkdir -p $(LIBCRT_BUILD_DIR)
	$(MAKE) -C $(LIBCRT_SRC_DIR) OUT_DIR=$(LIBCRT_BUILD_DIR) CC=$(CC)

# openssl
$(LIBCRYPTO): $(OPENSSL_MAKEFILE) $(LIBCRT)
	$(MAKE) -C $(OPENSSL_BUILD_DIR)

$(OPENSSL_MAKEFILE):
	mkdir -p $(OPENSSL_BUILD_DIR)
	(cd $(OPENSSL_BUILD_DIR) && \
		$(OPENSSL_SRC_DIR)/Configure \
			--cross-compile-prefix=$(CROSS_PREFIX) \
			--config=$(DEPS_DIR)/openssl_svsm.conf \
			--api=1.1.1 \
			SVSM \
			disable-legacy \
			no-afalgeng \
			no-aria \
			no-asm \
			no-async \
			no-atexit \
			no-autoerrinit \
			no-autoload-config \
			no-bf \
			no-blake2 \
			no-capieng \
			no-cast \
			no-chacha \
			no-cmac \
			no-cmp \
			no-cms \
			no-ct \
			no-deprecated \
			no-des \
			no-dgram \
			no-dh \
			no-docs \
			no-dsa \
			no-dso \
			no-dtls \
			no-dtls1 \
			no-dtls1-method \
			no-dtls1_2 \
			no-dtls1_2-method \
			no-dynamic-engine \
			no-ec2m \
			no-ecdh \
			no-ecdsa \
			no-ecx  \
			no-egd \
			no-engine \
			no-err \
			no-filenames \
			no-gost \
			no-http  \
			no-idea \
			no-ktls \
			no-makedepend \
			no-md4 \
			no-mdc2 \
			no-ml-dsa \
			no-ml-kem \
			no-module \
			no-multiblock \
			no-nextprotoneg \
			no-ocb \
			no-ocsp \
			no-padlockeng \
			no-pic \
			no-poly1305 \
			no-posix-io \
			no-psk \
			no-quic \
			no-rc2 \
			no-rc4 \
			no-rfc3779 \
			no-rmd160 \
			no-scrypt \
			no-seed \
			no-shared \
			no-siphash \
			no-siv \
			no-sm2 \
			no-sm2-precomp  \
			no-sm3 \
			no-sm4 \
			no-sock \
			no-srp \
			no-srtp \
			no-sse2 \
			no-ssl \
			no-ssl-trace \
			no-ssl3-method \
			no-static-engine \
			no-stdio \
			no-tests \
			no-thread-pool \
			no-threads \
			no-tls1 \
			no-tls1-method \
			no-tls1_1 \
			no-tls1_1-method \
			no-tls1_2 \
			no-tls1_2-method \
			no-tls1_3 \
			no-ts \
			no-ui-console \
			no-uplink \
			no-whirlpool \
			--with-rand-seed=getrandom \
			$(OPENSSL_CONFIG_TYPE) \
			-I$(LIBCRT_SRC_DIR)/include \
			-Wl,rpath=$(LIBCRT_BUILD_DIR) -lcrt)

# tcgtpm
$(LIBBNMATH): $(TCGTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBBNMATH_TARGET)

$(LIBTPMBIGNUM): $(TCGTPM_MAKEFILE) $(LIBBNMATH)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBTPMBIGNUM_TARGET)

$(LIBTPM): $(TCGTPM_MAKEFILE) $(LIBTPMBIGNUM)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBTPM_TARGET)

$(LIBPLATFORM): $(TCGTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBPLATFORM_TARGET)

TCGTPM_CFLAGS += -static -nostdinc -fno-stack-protector -fPIE -mno-sse -mno-red-zone
TCGTPM_CFLAGS += -DFILE_BACKED_NV=NO
TCGTPM_CFLAGS += -I$(LIBCRT_SRC_DIR)/include
TCGTPM_CFLAGS += -I$(OPENSSL_BUILD_DIR)/include
TCGTPM_CFLAGS += -I$(OPENSSL_SRC_DIR)/include

$(TCGTPM_MAKEFILE): $(LIBCRYPTO) $(LIBCRT)
	mkdir -p $(TCGTPM_BUILD_DIR)
	(cd $(TCGTPM_BUILD_DIR) && \
		cmake \
			-DCMAKE_SYSTEM_NAME=Generic	\
			-DCMAKE_C_COMPILER="$(CC)"	\
			-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
			-DCMAKE_C_FLAGS="${TCGTPM_CFLAGS}" \
			-DOPENSSL_CRYPTO_LIBRARY="$(LIBCRYPTO)" \
			-DOPENSSL_INCLUDE_DIR="$(OPENSSL_BUILD_DIR)/include" \
			-Duser_TpmConfiguration_Dir="$(DEPS_DIR)/TpmConfiguration" \
			$(TCGTPM_SRC_DIR))

clean:
	$(MAKE) -C $(LIBCRT_SRC_DIR) OUT_DIR=$(LIBCRT_BUILD_DIR) clean
	[ ! -f $(OPENSSL_MAKEFILE) ] || $(MAKE) -C $(OPENSSL_BUILD_DIR) clean
	[ ! -f $(TCGTPM_MAKEFILE) ] || $(MAKE) -C $(TCGTPM_BUILD_DIR) clean
	rm -f $(OUT_DIR)/libtcgtpm.a

distclean: clean
	rm -rf $(LIBCRT_BUILD_DIR)
	rm -rf $(OPENSSL_BUILD_DIR)
	rm -rf $(TCGTPM_BUILD_DIR)

.PHONY: all clean distclean

.PHONY: libcrt configure_openssl configure_tcgtpm libcrypto tcgtpm
libcrt: $(LIBCRT)
configure_openssl: $(OPENSSL_MAKEFILE)
libcrypto: $(LIBCRYPTO)
configure_tcgtpm: $(TCGTPM_MAKEFILE)
tcgtpm: $(OUT_DIR)/libtcgtpm.a
