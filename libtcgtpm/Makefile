ifeq ($(shell uname -m),x86_64)
CROSS_PREFIX :=
else
CROSS_PREFIX := x86_64-linux-gnu-
endif
CC := $(CROSS_PREFIX)gcc

ifdef RELEASE
TCGTPM_CFLAGS = -O3 -DDEBUG=NO
else
TCGTPM_CFLAGS = -g -O0 -DDEBUG=YES
endif

# Allow user to not link in libcrt
USE_LIBCRT ?= 1

# OpenSSL and libcrt are built externally (by cocoon-tpm-ossl-bare-sys
# and the libcrt crate respectively).
# The following must be provided by the caller:
#   OPENSSL_INCLUDE_DIR, OPENSSL_SRC_INCLUDE_DIR, OPENSSL_LIB_DIR
#   LIBCRT_INCLUDE_DIR

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

TCGTPM_SRC_DIR = $(DEPS_DIR)/tpm-20-ref/TPMCmd

TCGTPM_BUILD_DIR = $(OUT_DIR)/tcgtpm-build

LIBCRYPTO = $(OPENSSL_LIB_DIR)/libcrypto.a

LIBTPM_TARGET = Tpm_CoreLib
LIBTPM = $(TCGTPM_BUILD_DIR)/tpm/src/lib$(LIBTPM_TARGET).a

LIBPLATFORM_TARGET = Tpm_PlatformLib
LIBPLATFORM = $(TCGTPM_BUILD_DIR)/Platform/lib$(LIBPLATFORM_TARGET).a

LIBTPMBIGNUM_TARGET = Tpm_CryptoLib_TpmBigNum
LIBTPMBIGNUM = $(TCGTPM_BUILD_DIR)/tpm/cryptolibs/TpmBigNum/lib$(LIBTPMBIGNUM_TARGET).a

LIBBNMATH_TARGET = Tpm_CryptoLib_Math_Ossl
LIBBNMATH = $(TCGTPM_BUILD_DIR)/cryptolib_Ossl/lib$(LIBBNMATH_TARGET).a

TCGTPM_MAKEFILE = $(TCGTPM_BUILD_DIR)/Makefile

ifeq ($(USE_LIBCRT),1)
TCGTPM_CFLAGS += -static -nostdinc -fno-stack-protector -mno-sse -mno-red-zone
TCGTPM_CFLAGS += -I$(LIBCRT_INCLUDE_DIR)
endif

# Avoid running jobs of this Makefile in parallel to avoid possible conflicts
# when building the TPM libraries, which use the same Makefile and subdirectory.
# Parallel builds are still used inside the sub-targets (-j flag)
.NOTPARALLEL:

all: $(LIBBNMATH) $(LIBTPMBIGNUM) $(LIBTPM) $(LIBPLATFORM)

# tcgtpm
$(LIBBNMATH): $(TCGTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBBNMATH_TARGET)

$(LIBTPMBIGNUM): $(TCGTPM_MAKEFILE) $(LIBBNMATH)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBTPMBIGNUM_TARGET)

$(LIBTPM): $(TCGTPM_MAKEFILE) $(LIBTPMBIGNUM)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBTPM_TARGET)

$(LIBPLATFORM): $(TCGTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(TCGTPM_BUILD_DIR) $(LIBPLATFORM_TARGET)

TCGTPM_CFLAGS += -fPIE
TCGTPM_CFLAGS += -DFILE_BACKED_NV=YES -DVTPM=YES
TCGTPM_CFLAGS += -I$(OPENSSL_INCLUDE_DIR)
TCGTPM_CFLAGS += -I$(OPENSSL_SRC_INCLUDE_DIR)

$(TCGTPM_MAKEFILE): $(LIBCRYPTO)
	mkdir -p $(TCGTPM_BUILD_DIR)
	(cd $(TCGTPM_BUILD_DIR) && \
		cmake \
			-DCMAKE_SYSTEM_NAME=Generic	\
			-DCMAKE_C_COMPILER="$(CC)"	\
			-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
			-DCMAKE_C_FLAGS="${TCGTPM_CFLAGS}" \
			-DOPENSSL_CRYPTO_LIBRARY="$(LIBCRYPTO)" \
			-DOPENSSL_INCLUDE_DIR="$(OPENSSL_INCLUDE_DIR)" \
			-Duser_TpmConfiguration_Dir="$(DEPS_DIR)/TpmConfiguration" \
			$(TCGTPM_SRC_DIR))

clean:
	[ ! -f $(TCGTPM_MAKEFILE) ] || $(MAKE) -C $(TCGTPM_BUILD_DIR) clean

distclean: clean
	rm -rf $(TCGTPM_BUILD_DIR)

.PHONY: all clean distclean configure_tcgtpm
configure_tcgtpm: $(TCGTPM_MAKEFILE)
