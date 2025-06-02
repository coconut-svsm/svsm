/* SPDX-License-Identifier: MIT */

#include <libcrt.h>

#define NOT_IMPLEMENTED printf("WARNING: %s not implemented\n", __func__)

// errno.h

int  errno = 0;
FILE  *stderr = NULL;
FILE  *stdin  = NULL;
FILE  *stdout = NULL;

char *strerror(int errnum)
{
    NOT_IMPLEMENTED;
    return NULL;
}

// stdio.h

int sscanf(const char  *buffer, const char  *format, ...)
{
    NOT_IMPLEMENTED;
    return 0;
}

size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
{
    NOT_IMPLEMENTED;
    return 0;
}

size_t fread(void *b, size_t c, size_t i, FILE *f)
{
    NOT_IMPLEMENTED;
    return 0;
}

int fclose(FILE *f)
{
    NOT_IMPLEMENTED;
    return EOF;
}

FILE *fopen(const char *c, const char *m)
{
    NOT_IMPLEMENTED;
    return NULL;
}

int fputc(int c, FILE *f) 
{
    NOT_IMPLEMENTED;
    return 0;
}


void setbuf(FILE *stream, char *buf)
{
    NOT_IMPLEMENTED;
}

int ferror(FILE *stream) {
	NOT_IMPLEMENTED;
	return -1;
}

int clearerr(FILE *stream) {
	NOT_IMPLEMENTED;
	return -1;
}

// stdlib.h

long strtol(const char *nptr, char **endptr, int base)
{
    NOT_IMPLEMENTED;
    return LONG_MIN;
}

unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    NOT_IMPLEMENTED;
    return ULONG_MAX;
}

char *getenv(const char *varname)
{
    NOT_IMPLEMENTED;
    return NULL;
}

int atexit(void (*func)(void))
{
    NOT_IMPLEMENTED;
    return 0;
}

// unistd.h

pid_t getpid(void)
{
    // TODO: return the actual PID when CPL3 is supported
    return 0;
}

uid_t getuid(void)
{
    NOT_IMPLEMENTED;
    return 0;
}

uid_t geteuid(void)
{
    NOT_IMPLEMENTED;
    return 0;
}

gid_t getgid(void)
{
    NOT_IMPLEMENTED;
    return 0;
}

gid_t getegid(void)
{
    NOT_IMPLEMENTED;
    return 0;
}

long syscall(long number, ...)
{
    NOT_IMPLEMENTED;
    errno = ENOSYS;
    return -1;
}

int usleep(useconds_t usec)
{
    NOT_IMPLEMENTED;
    return -1;
}

unsigned int sleep(unsigned int seconds)
{
    NOT_IMPLEMENTED;
    return seconds;
}

int timezone = 0;

// dirent.h

DIR *opendir(const char *name)
{
    NOT_IMPLEMENTED;
    return NULL;
}

int closedir(DIR *name)
{
    NOT_IMPLEMENTED;
    return -1;
}

struct dirent *readdir(DIR *name)
{
    NOT_IMPLEMENTED;
    return NULL;
}

// sys/stat.h

int stat(const char *__restrict path, struct stat *restrict buf)
{
    NOT_IMPLEMENTED;
    return -1;
}

// time.h

char *ctime(const time_t *t) {
    NOT_IMPLEMENTED;
    return NULL;
}

time_t mktime(struct tm *tm) {
    NOT_IMPLEMENTED;
    return 0;
}
