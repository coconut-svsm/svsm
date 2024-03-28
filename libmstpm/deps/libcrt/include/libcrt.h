/* SPDX-License-Identifier: MIT */

#ifndef __LIBCRT_H__
#define __LIBCRT_H__

// The SVSM guids are expected to be the last bytes of the svsm.bin file. When
// we set the external dependencies symbols to be hidden, we prevent them from
// being preempted. Otherwise, the SVSM guids will not be the last bytes of the
// svsm.bin.
#if defined(__pie__)
#pragma GCC visibility push (hidden)
#endif

// Openssl big number operation (bn_op). Ensure it is defined for all SVSM
// external dependency that requires openssl crypto functions.
//#define SIXTY_FOUR_BIT_LONG
#define SIXTY_FOUR_BIT

// features.h

#define _Noreturn __attribute__((__noreturn__))

#define hidden __attribute__((__visibility__("hidden")))
#define weak_alias(old, new) \
        extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))

// All types required

#define __NEED_va_list

#define __NEED_int8_t
#define __NEED_int16_t
#define __NEED_int32_t
#define __NEED_int64_t

#define __NEED_uint8_t
#define __NEED_uint16_t
#define __NEED_uint32_t
#define __NEED_uint64_t

#define __NEED_intptr_t
#define __NEED_uintptr_t
#define __NEED_size_t
#define __NEED_ssize_t
#define __NEED_ptrdiff_t
#define __NEED_wchar_t

#define __NEED_intmax_t
#define __NEED_uintmax_t

#define __NEED_time_t
#define __NEED_clock_t
#define __NEED_clockid_t
#define __NEED_struct_timespec

#define __NEED_pid_t
#define __NEED_FILE
#define __NEED_struct__IO_FILE

#define __NEED_dev_t
#define __NEED_ino_t
#define __NEED_mode_t
#define __NEED_nlink_t
#define __NEED_uid_t
#define __NEED_gid_t
#define __NEED_off_t
#define __NEED_blksize_t
#define __NEED_blkcnt_t

#include <bits/alltypes.h>

// errno.h

extern int errno;
#define EINTR         4
#define ENOMEM        12
#define EINVAL        22
#define ENOSYS        38
#define EAFNOSUPPORT  47
#define EOVERFLOW     75

// stddef.h

#ifndef NULL
#define NULL  ((void *) 0)
#endif

#define offsetof(type, member) __builtin_offsetof(type, member)

// stdbool.h

#define true 1
#define false 0
#define bool _Bool

// stdint.h

#define INT8_MIN   (-1-0x7f)
#define INT16_MIN  (-1-0x7fff)
#define INT32_MIN  (-1-0x7fffffff)
#define INT64_MIN  (-1-0x7fffffffffffffff)

#define INT8_MAX   (0x7f)
#define INT16_MAX  (0x7fff)
#define INT32_MAX  (0x7fffffff)
#define INT64_MAX  (0x7fffffffffffffff)

#define UINT8_MAX  (0xff)
#define UINT16_MAX (0xffff)
#define UINT32_MAX (0xffffffffu)
#define UINT64_MAX (0xffffffffffffffffu)

// limits.h

#define UCHAR_MAX  255
#define SSIZE_MAX  0xFFFFFFFFFFFFFFFFU
#define INT_MIN  (-1-0x7fffffff)
#define INT_MAX  0x7fffffff
#define LONG_MIN (-LONG_MAX-1)
#define LONG_MAX __LONG_MAX
#define UINT_MAX 0xffffffffU
#define ULONG_MAX (2UL*LONG_MAX+1)
#define CHAR_BIT 8

// atomic.h

// Check the atomic.h file for the atomic definitions. It is a busy file with
// lots of inline functions and it also includes architecture dependent code.

// stdarg.h

#define va_start(v,l)   __builtin_va_start(v,l)
#define va_end(v)       __builtin_va_end(v)
#define va_arg(v,l)     __builtin_va_arg(v,l)
#define va_copy(d,s)    __builtin_va_copy(d,s)

// unistd.h

#define STDERR_FILENO 2
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

pid_t getpid(void);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int issetugid(void);

int getentropy(void *buffer, size_t length);
long syscall(long number, ...);
int usleep(unsigned usec);

// stdio.h

#define EOF (-1)
#define BUFSIZ  8192
void setbuf(FILE *stream, char *buf);
int printf(const char *restrict fmt, ...);
int dprintf(int fd, const char *__restrict fmt, ...);
int vdprintf(int fd, const char *restrict fmt, va_list ap);
int puts(const char *s);
int fprintf(FILE *restrict f, const char *restrict fmt, ...);
int asprintf(char **s, const char *fmt, ...);
int snprintf(char *restrict s, size_t n, const char *restrict fmt, ...);
int sprintf(char *restrict s, const char *restrict fmt, ...);
int vasprintf(char **s, const char *fmt, va_list ap);
int vsnprintf(char *restrict s, size_t n, const char *restrict fmt, va_list ap);
int vsprintf(char *restrict s, const char *restrict fmt, va_list ap);

int vprints(const char *format, va_list ap);
int vsnprints(char *str, size_t size, const char *format, va_list ap);

// Functions exported by the SVSM
extern void serial_out(const char *s, int len);

// stdlib.h

// Functions exported by the SVSM
extern void *malloc(size_t size);
extern void *realloc(void *ptr, size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern void free(void *ptr);
extern _Noreturn void abort(void);

int atoi(const char *s);
int atexit(void (*func)(void));

void qsort(void *, size_t, size_t,  int (*)(const void *, const void *));
void qsort_r(void *, size_t, size_t, int (*)(const void *, const void *, void *), void *);
void __qsort_r(void *, size_t, size_t, int (*)(const void *, const void *, void *), void *);

char *getenv(const char *);

int rand(void);
void srand(unsigned s);

// time.h

#define CLOCK_MONOTONIC          1

struct tm {
  int tm_sec;     /* seconds after the minute [0-60] */
  int tm_min;     /* minutes after the hour [0-59] */
  int tm_hour;    /* hours since midnight [0-23] */
  int tm_mday;    /* day of the month [1-31] */
  int tm_mon;     /* months since January [0-11] */
  int tm_year;    /* years since 1900 */
  int tm_wday;    /* days since Sunday [0-6] */
  int tm_yday;    /* days since January 1 [0-365] */
  int tm_isdst;   /* Daylight Savings Time flag */
  long tm_gmtoff; /* offset from CUT in seconds */
  char *tm_zone;  /* timezone abbreviation */
};

struct timeval {
  long tv_sec;  /* time value, in seconds */
  long tv_usec; /* time value, in microseconds */
};

char *ctime(const time_t *t);
time_t time(time_t *);
struct tm *gmtime(const time_t *);
struct tm *gmtime_r(const time_t *restrict t, struct tm *restrict tm);
clock_t clock(void);
int clock_gettime(clockid_t clk_id, struct timespec *tp);
int gettimeofday(struct timeval *restrict tv, void *restrict tz);
int __secs_to_tm(long long t, struct tm *tm);

#define DECLARE_ARGS(val, low, high)	unsigned long low, high
#define EAX_EDX_VAL(val, low, high)	((low) | (high) << 32)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)

static inline unsigned long long rdtsc(void)
{
	DECLARE_ARGS(val, low, high);
	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));
	return EAX_EDX_VAL(val, low, high);
}

// inttypes.h

#if UINTPTR_MAX == UINT64_MAX
#define __PRI64  "l"
#define __PRIPTR "l"
#else
#define __PRI64  "ll"
#define __PRIPTR ""
#endif

#define PRIu8  "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 __PRI64 "u"

// dirent.h

typedef struct __dirstream DIR;

struct dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

DIR *opendir(const char *name);
int closedir(DIR *name);
struct dirent *readdir(DIR *name);

typedef unsigned long __jmp_buf[8];

typedef struct __jmp_buf_tag {
	__jmp_buf __jb;
	unsigned long __fl;
	unsigned long __ss[128/sizeof(long)];
} jmp_buf[1];

#define __setjmp_attr __attribute__((__returns_twice__))

// sys/stat.h

#define S_IFDIR 0040000
#define S_IFMT  0170000

#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)

/* copied from kernel definition, but with padding replaced
 * by the corresponding correctly-sized userspace types. */
struct stat {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;

    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    unsigned int    __pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;

    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long __unused[3];
};

int stat(const char *__restrict path, struct stat *restrict buf);

// string.h

void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);
void *memchr(const void *src, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memrchr(const void *m, int c, size_t n);
void *__memrchr(const void *m, int c, size_t n);

int strcmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strrchr(const char *, int);
unsigned long strtoul(const char *, char **, int);
long strtol(const char *, char **, int);
char *strerror(int);
size_t strspn(const char *, const char *);
size_t strcspn(const char *, const char *);

char *strcpy(char *strDest, const char  *strSource);
size_t strlen(const char *s);
char *__strchrnul(const char *s, int c);
char *__stpcpy(char *restrict d, const char *restrict s);
char *__stpncpy(char *restrict d, const char *restrict s, size_t n);
char *strstr(const char *h, const char *n);
char *strdup(const char *s);
char *strncpy(char *restrict d, const char *restrict s, size_t n);
int strncmp(const char *_l, const char *_r, size_t n);
int strcasecmp(const char *_l, const char *_r);
char *strcat(char *restrict dest, const char *restrict src);
char *strncat (char *__restrict, const char *__restrict, size_t);

// ctype.h

int isdigit(int c);
int isspace(int c);
int isupper(int c);
int isascii(int c);
int islower(int c);

int tolower(int c);
int toupper(int c);

// stdio.h

int printf(const char *, ...);
int sscanf(const char *, const char *, ...);

FILE *fopen(const char *, const char *);
int fclose(FILE *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream);
int fprintf(FILE *, const char *, ...);
int fputc(int c, FILE *f);

int ferror(FILE *stream);
int clearerr(FILE *stream);

int vasprintf(char **s, const char *fmt, va_list ap);
int asprintf(char **s, const char *fmt, ...);
int vsnprintf(char *restrict s, size_t n, const char *restrict fmt, va_list ap);
int vsprintf(char *restrict s, const char *restrict fmt, va_list ap);
int snprintf(char *restrict s, size_t n, const char *restrict fmt, ...);
int sprintf(char *restrict s, const char *restrict fmt, ...);
int dprintf(int fd, const char *__restrict fmt, ...);
int vdprintf(int fd, const char *restrict fmt, va_list ap);

// inet.h

int inet_pton(int, const char *, void *);

// setjmp.h

int setjmp (jmp_buf) __setjmp_attr;
_Noreturn void longjmp (jmp_buf, int);

// assert.h

#define assert(x) ((void)((x) || (__assert_fail(#x, __FILE__, __LINE__, __func__),0)))
_Noreturn void __assert_fail (const char *, const char *, int, const char *);

#endif
