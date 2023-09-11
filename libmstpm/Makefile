DEPS_DIR = $(CURDIR)/deps

LIBCRT_DIR = $(DEPS_DIR)/libcrt

LIBCRT = $(LIBCRT_DIR)/libcrt.a

LIBS = $(LIBCRT)

all: libmstpm.a

libmstpm.a: $(LIBS)
	rm -f $@
	ar rcsTPD $@ $^

# libcrt
$(LIBCRT):
	$(MAKE) -C $(LIBCRT_DIR)

clean:
	make -C $(LIBCRT_DIR) clean
	rm -f libmstpm.a

distclean: clean

.PHONY: all clean distclean
