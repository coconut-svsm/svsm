/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdarg.h>

int fprintf(FILE *restrict f, const char *restrict fmt, ...)
{
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vprints(fmt, ap);
	va_end(ap);
	return ret;
}
