ifdef RELEASE
OPENSSL_CONFIG_TYPE = --release
else
OPENSSL_CONFIG_TYPE = --debug
endif

DEPS_DIR = $(CURDIR)/deps

LIBCRT_DIR = $(DEPS_DIR)/libcrt
OPENSSL_DIR = $(DEPS_DIR)/openssl

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a

OPENSSL_MAKEFILE = $(OPENSSL_DIR)/Makefile

LIBS = $(LIBCRT) $(LIBCRYPTO)

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
			--with-rand-seed=none \
			$(OPENSSL_CONFIG_TYPE) \
			-I$(LIBCRT_DIR)/include \
			-Wl,rpath=$(LIBCRT_DIR) -lcrt)

clean: $(OPENSSL_MAKEFILE)
	make -C $(LIBCRT_DIR) clean
	make -C $(OPENSSL_DIR) clean
	rm -f libmstpm.a

distclean: clean
	rm -f $(OPENSSL_MAKEFILE)

.PHONY: all clean distclean
