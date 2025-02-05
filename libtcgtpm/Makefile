ifdef RELEASE
OPENSSL_CONFIG_TYPE = --release
TCGTPM_CFLAGS = -O3 -DDEBUG=NO
else
OPENSSL_CONFIG_TYPE = --debug
TCGTPM_CFLAGS = -g -O0 -DDEBUG=YES
endif

DEPS_DIR = $(CURDIR)/deps

LIBCRT_DIR = $(DEPS_DIR)/libcrt
OPENSSL_DIR = $(DEPS_DIR)/openssl
TCGTPM_DIR = $(DEPS_DIR)/tpm-20-ref/TPMCmd

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a

LIBTPM_A = tpm/src/libtpm.a
LIBTPM = $(TCGTPM_DIR)/$(LIBTPM_A)

LIBPLATFORM_A = Platform/src/libplatform.a
LIBPLATFORM = $(TCGTPM_DIR)/$(LIBPLATFORM_A)

OPENSSL_MAKEFILE = $(OPENSSL_DIR)/Makefile
TCGTPM_MAKEFILE = $(TCGTPM_DIR)/Makefile

LIBS = $(LIBCRT) $(LIBCRYPTO) $(LIBTPM) $(LIBPLATFORM)

OUT_DIR ?= $(CWD)

all: $(OUT_DIR)/libtcgtpm.a

$(OUT_DIR)/libtcgtpm.a: $(LIBS)
	rm -f $@
	ar rcsTPD $@ $^

# libcrt
$(LIBCRT):
	$(MAKE) -C $(LIBCRT_DIR)

# openssl
$(LIBCRYPTO): $(OPENSSL_MAKEFILE) $(LIBCRT)
	$(MAKE) -C $(OPENSSL_DIR) -j$$(nproc)

$(OPENSSL_MAKEFILE):
	(cd $(OPENSSL_DIR) && \
		./Configure \
			--config=$(DEPS_DIR)/openssl_svsm.conf \
			SVSM \
			no-afalgeng \
			no-async \
			no-autoerrinit \
			no-autoload-config \
			no-bf \
			no-blake2 \
			no-capieng \
			no-cast \
			no-chacha \
			no-cms \
			no-ct \
			no-deprecated \
			no-des \
			no-dgram \
			no-dsa \
			no-dynamic-engine \
			no-ec2m \
			no-engine \
			no-err \
			no-filenames \
			no-gost \
			no-hw \
			no-idea \
			no-md4 \
			no-mdc2 \
			no-pic \
			no-ocb \
			no-poly1305 \
			no-posix-io \
			no-rc2 \
			no-rc4 \
			no-rfc3779 \
			no-rmd160 \
			no-scrypt \
			no-seed \
			no-sock \
			no-srp \
			no-ssl \
			no-stdio \
			no-threads \
			no-ts \
			no-whirlpool \
			no-shared \
			no-sse2 \
			no-ui-console \
			no-asm \
			--with-rand-seed=getrandom \
			$(OPENSSL_CONFIG_TYPE) \
			-I$(LIBCRT_DIR)/include \
			-Wl,rpath=$(LIBCRT_DIR) -lcrt)

# tcgtpm
$(LIBTPM): $(TCGTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -j$$(nproc) -C $(TCGTPM_DIR) $(LIBTPM_A)

$(LIBPLATFORM): $(TCGTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -j$$(nproc) -C $(TCGTPM_DIR) $(LIBPLATFORM_A)

TCGTPM_CFLAGS += -static -nostdinc -fno-stack-protector -fPIE -mno-sse -mno-red-zone
TCGTPM_CFLAGS += -DFILE_BACKED_NV=NO
TCGTPM_CFLAGS += -I$(LIBCRT_DIR)/include
TCGTPM_CFLAGS += -I$(OPENSSL_DIR)/include
# This is needed to workaround an issue with an unused variable when
# FILE_BACKED_NV is set to NO. The real fix is posted here:
# https://github.com/TrustedComputingGroup/TPM/pull/7
# When that PR is merged, we can remove this line.
TCGTPM_CFLAGS += -Wno-error=unused-variable

TCGTPM_EXTRA_CFLAGS = -I $(DEPS_DIR)/TpmConfiguration

# Configure the TPM 2.0 Reference Implementation and remove the pthread requirement.
# In fact, pthread is required only in the TPM simulator, but we
# are not building the simulator.
#
# The https://github.com/TrustedComputingGroup/TPM/pull/7 will add support
# for `--disable-pthread` in configure, for now let's do a hack and set
# `ax_pthread_ok` to yes to make configure happy.
$(TCGTPM_MAKEFILE):
	(cd $(TCGTPM_DIR) && \
		./bootstrap && \
		sed -i 's/^ax_pthread_ok=no/ax_pthread_ok=yes/' configure && \
		./configure \
			EXTRA_CFLAGS="${TCGTPM_EXTRA_CFLAGS}" \
			CFLAGS="${TCGTPM_CFLAGS}" \
			LIBCRYPTO_LIBS="$(LIBCRT) $(LIBCRYPTO)" \
			LIBCRYPTO_CFLAGS="${TCGTPM_CFLAGS}")

clean: $(OPENSSL_MAKEFILE) $(TCGTPM_MAKEFILE)
	make -C $(LIBCRT_DIR) clean
	make -C $(OPENSSL_DIR) clean
	make -C $(TCGTPM_DIR) clean
	rm -f libtcgtpm.a

distclean: clean
	rm -f $(OPENSSL_MAKEFILE)
	rm -f $(TCGTPM_MAKEFILE)

.PHONY: all clean distclean
