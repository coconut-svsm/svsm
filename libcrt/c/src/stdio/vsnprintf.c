/* SPDX-License-Identifier: MIT */

#include <string.h>
#include <stdarg.h>

int vsnprintf(char *restrict s, size_t n, const char *restrict fmt, va_list ap)
{
	return vsnprints(s, n, fmt, ap);
}
