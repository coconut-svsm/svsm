# SPDX-License-Identifier: MIT

ifdef RELEASE
CFLAGS = -O3
else
CFLAGS = -g -O0
endif

CFLAGS += -I./include -nostdinc -nostdlib -mno-red-zone
CFLAGS += -m64 -march=x86-64 -mno-sse2 -fPIE
CFLAGS += -fno-stack-protector
CFLAGS += -ffreestanding
CFLAGS += -Wall -Werror

CC = gcc

# Functions we stub out
OBJS = src/stub.o

# ctype
OBJS += $(addprefix src/ctype/, \
				isdigit.o \
				islower.o \
				isspace.o \
				isupper.o \
				tolower.o \
				toupper.o \
				)
# exit
OBJS += src/exit/assert.o

# prng
OBJS += src/prng/rand.o

# setjmp
OBJS += $(addprefix src/setjmp/x86_64/, \
				longjmp.o \
				setjmp.o \
				)
# stdio
OBJS += $(addprefix src/stdio/, \
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
OBJS += $(addprefix src/stdlib/, \
				atoi.o \
				qsort.o \
				qsort_nr.o \
				)
# string
OBJS += $(addprefix src/string/, \
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
OBJS += $(addprefix src/time/, \
				__secs_to_tm.o \
				gmtime_r.o \
				time.o \
				)

all: libcrt.a

libcrt.a: $(OBJS)
	ar rcs $@ $(OBJS)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o : %.s
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f libcrt.a
	rm -f $(OBJS)
