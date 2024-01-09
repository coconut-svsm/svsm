ifdef RELEASE
OPENSSL_CONFIG_TYPE = --release
MSTPM_CFLAGS = -O3 -DDEBUG=NO
else
OPENSSL_CONFIG_TYPE = --debug
MSTPM_CFLAGS = -g -O0 -DDEBUG=YES
endif

DEPS_DIR = $(CURDIR)/deps

LIBCRT_DIR = $(DEPS_DIR)/libcrt
OPENSSL_DIR = $(DEPS_DIR)/openssl
MSTPM_DIR = $(DEPS_DIR)/ms-tpm-20-ref/TPMCmd

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a

LIBTPM_A = tpm/src/libtpm.a
LIBTPM = $(MSTPM_DIR)/$(LIBTPM_A)

LIBPLATFORM_A = Platform/src/libplatform.a
LIBPLATFORM = $(MSTPM_DIR)/$(LIBPLATFORM_A)

OPENSSL_MAKEFILE = $(OPENSSL_DIR)/Makefile
MSTPM_MAKEFILE = $(MSTPM_DIR)/Makefile

LIBS = $(LIBCRT) $(LIBCRYPTO) $(LIBTPM) $(LIBPLATFORM)

all: libmstpm.a

libmstpm.a: $(LIBS)
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

# ms-tpm
$(LIBTPM): $(MSTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(MSTPM_DIR) $(LIBTPM_A)

$(LIBPLATFORM): $(MSTPM_MAKEFILE) $(LIBCRYPTO)
	$(MAKE) -C $(MSTPM_DIR) $(LIBPLATFORM_A)

MSTPM_CFLAGS += -static -nostdinc -fno-stack-protector -fPIE -mno-sse
MSTPM_CFLAGS += -DSIMULATION=NO -DFILE_BACKED_NV=NO
MSTPM_CFLAGS += -I$(LIBCRT_DIR)/include
MSTPM_CFLAGS += -I$(OPENSSL_DIR)/include

# Configure the Microsoft TPM and remove the pthread requirement.
# In fact, pthread is required only in the TPM simulator, but we
# are not building the simulator.
$(MSTPM_MAKEFILE):
	(cd $(MSTPM_DIR) && \
		sed -i '/^AX_PTHREAD/d' configure.ac && \
		./bootstrap && \
		./configure \
			CFLAGS="${MSTPM_CFLAGS}" \
			LIBCRYPTO_LIBS="${$(LIBCRT) $(LIBCRYPTO)}")

clean: $(OPENSSL_MAKEFILE) $(MSTPM_MAKEFILE)
	make -C $(LIBCRT_DIR) clean
	make -C $(OPENSSL_DIR) clean
	sed -i '/^AX_PTHREAD/d' $(MSTPM_DIR)/configure.ac
	make -C $(MSTPM_DIR) clean
	rm -f libmstpm.a

distclean: clean
	rm -f $(OPENSSL_MAKEFILE)
	rm -f $(MSTPM_MAKEFILE)

.PHONY: all clean distclean
