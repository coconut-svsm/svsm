# SPDX-License-Identifier: MIT

ifdef RELEASE
CFLAGS = -O3
else
CFLAGS = -g -O0
endif

SRC_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
OUT_DIR ?= $(SRC_DIR)

CFLAGS += -I$(SRC_DIR)/include -nostdinc -nostdlib -mno-red-zone
CFLAGS += -m64 -march=x86-64 -mno-sse2 -fPIE
CFLAGS += -fno-stack-protector
CFLAGS += -ffreestanding
CFLAGS += -Wall -Werror

CC = gcc

vpath %.c $(SRC_DIR)
vpath %.s $(SRC_DIR)

# Functions we stub out
OBJS = $(OUT_DIR)/src/stub.o

# ctype
OBJS += $(addprefix $(OUT_DIR)/src/ctype/, \
				isdigit.o \
				islower.o \
				isspace.o \
				isupper.o \
				tolower.o \
				toupper.o \
				)
# exit
OBJS += $(OUT_DIR)/src/exit/assert.o

# prng
OBJS += $(OUT_DIR)/src/prng/rand.o

# setjmp
OBJS += $(addprefix $(OUT_DIR)/src/setjmp/x86_64/, \
				longjmp.o \
				setjmp.o \
				)
# stdio
OBJS += $(addprefix $(OUT_DIR)/src/stdio/, \
				asprintf.o \
				fprintf.o \
				printf.o \
				printf_wrapper.o \
				snprintf.o \
				sprintf.o \
				vasprintf.o \
				vsnprintf.o \
				vsprintf.o \
				)
# stdlib
OBJS += $(addprefix $(OUT_DIR)/src/stdlib/, \
				atoi.o \
				qsort.o \
				qsort_nr.o \
				)
# string
OBJS += $(addprefix $(OUT_DIR)/src/string/, \
				memchr.o \
				memcmp.o \
				memcpy.o \
				memmove.o \
				memrchr.o \
				memset.o \
				stpcpy.o \
				stpncpy.o \
				strcasecmp.o \
				strcat.o \
				strchr.o \
				strchrnul.o \
				strcmp.o \
				strcspn.o \
				strcpy.o \
				strdup.o \
				strlen.o \
				strncasecmp.o \
				strncat.o \
				strncmp.o \
				strncpy.o \
				strrchr.o \
				strspn.o \
				strstr.o \
				)
# time
OBJS += $(addprefix $(OUT_DIR)/src/time/, \
				__secs_to_tm.o \
				gmtime_r.o \
				time.o \
				)

all: $(OUT_DIR)/libcrt.a

$(OUT_DIR)/libcrt.a: $(OBJS)
	ar rcs $@ $(OBJS)

$(OUT_DIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT_DIR)/%.o : %.s
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OUT_DIR)/libcrt.a
	rm -f $(OBJS)
