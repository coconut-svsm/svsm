/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

enum {
	LEN_MOD_INVALID		= 0,
	LEN_MOD_HALF_HALF,
	LEN_MOD_HALF,
	LEN_MOD_INT,
	LEN_MOD_LONG,
	LEN_MOD_LONG_LONG,
	LEN_MOD_MAX
};

static char *format_string(char *cur, char *end, va_list ap)
{
	char *tmp = va_arg(ap, char *);

	while (*tmp) {
		if (cur < end)
			*cur = *tmp;
		cur++;
		tmp++;
	}

	return cur;
}

static char *format_base16(char *cur, char *end, int width, va_list ap)
{
	unsigned long long num;
	char *tmp, buffer[32];
	unsigned int size;
	char *map;

	map = "0123456789abcdef";

	if (cur < end)
		*cur++ = '0';
	if (cur < end)
		*cur++ = 'x';

	if (width == LEN_MOD_HALF_HALF) {
		unsigned char n = (unsigned char) va_arg(ap, int);
		num = (unsigned long long)n;
		size = 1;
	} else if (width == LEN_MOD_HALF) {
		unsigned short n = (unsigned short) va_arg(ap, int);
		num = (unsigned long long)n;
		size = 2;
	} else if (width == LEN_MOD_INT) {
		unsigned int n = (unsigned int) va_arg(ap, int);
		num = (unsigned long long)n;
		size = 4;
	} else if (width == LEN_MOD_LONG) {
		unsigned long n = (unsigned long) va_arg(ap, long);
		num = (unsigned long long)n;
		size = 8;
	} else {
		unsigned long long n = (unsigned long long) va_arg(ap, long long);
		num = (unsigned long long)n;
		size = 8;
	}

	tmp = buffer + sizeof(buffer);

	tmp--;
	*tmp = '\0';
	while (size--) {
		tmp--;
		*tmp = map[num & 0xf];
		num >>= 4;

		tmp--;
		*tmp = map[num & 0xf];
		num >>= 4;
	}

	while (*tmp) {
		if (cur < end)
			*cur = *tmp;
		cur++;
		tmp++;
	}

	return cur;
}

static char *format_base10(char *cur, char *end, int width, bool signed_format, va_list ap)
{
	unsigned long long num;
	char *tmp, buffer[32];

	if (width == LEN_MOD_HALF_HALF) {
		unsigned char n = (unsigned char) va_arg(ap, int);
		if (signed_format && (char)n < 0) {
			if (cur < end)
				*cur++ = '-';
			n = -(char)n;
		}
		num = (unsigned long long)n;
	} else if (width == LEN_MOD_HALF) {
		unsigned short n = (unsigned short) va_arg(ap, int);
		if (signed_format && (short)n < 0) {
			if (cur < end)
				*cur++ = '-';
			n = -(short)n;
		}
		num = (unsigned long long)n;
	} else if (width == LEN_MOD_INT) {
		unsigned int n = (unsigned int) va_arg(ap, int);
		if (signed_format && (int)n < 0) {
			if (cur < end)
				*cur++ = '-';
			n = -(int)n;
		}
		num = (unsigned long long)n;
	} else if (width == LEN_MOD_LONG) {
		unsigned long n = (unsigned long) va_arg(ap, long);
		if (signed_format && (long)n < 0) {
			if (cur < end)
				*cur++ = '-';
			n = -(long)n;
		}
		num = (unsigned long long)n;
	} else {
		unsigned long long n = (unsigned long long) va_arg(ap, long long);
		if (signed_format && (long long)n < 0) {
			if (cur < end)
				*cur++ = '-';
			n = -(long long)n;
		}
		num = (unsigned long long)n;
	}

	tmp = buffer + sizeof(buffer);

	tmp--;
	*tmp = '\0';
	do {
		tmp--;
		*tmp = (char)('0' + num % 10);

		num /= 10;
	} while (num);

	while (*tmp) {
		if (cur < end)
			*cur = *tmp;

		cur++;
		tmp++;
	}

	return cur;
}

int vsnprints(char *str, size_t size, const char *format, va_list ap)
{
	unsigned int width;
	char *cur, *end;
	bool convert;

	cur = str;
	end = cur + size;
	if (end < cur) {
		end = (void *)-1;
		size = end - cur;
	}

	convert = false;
	while (*format) {
		if (!convert) {
			if (*format != '%') {
				if (cur < end)
					*cur = *format;

				cur++;
				format++;
				continue;
			}

			format++;
			if (*format == '%') {
				if (cur < end)
					*cur = '%';

				cur++;
				format++;
				continue;
			}

			convert = true;
			width = LEN_MOD_INT;
		} else {
			bool signed_format = false;

			switch (*format) {
			case 'h':
				width--;
				if (width == LEN_MOD_INVALID)
					convert = false;
				break;
			case 'l':
				width++;
				if (width == LEN_MOD_MAX)
					convert = false;
				break;
			case 'd':
				signed_format = true;
			case 'z':
				// handle %zu
				if (*(format+1) && *(format+1) == 'u' )
					format++;
			case 'u':
				cur = format_base10(cur, end, width, signed_format, ap);
				convert = false;
				break;
			case 'p':
				width = LEN_MOD_LONG;
			case 'x':
				cur = format_base16(cur, end, width, ap);
				convert = false;
				break;
			case 's': {
				cur = format_string(cur, end, ap);
				convert = false;
				break;
			}
			default:
				convert = false;
			}

			format++;
		}
	}

	if (size) {
		if (cur < end)
			*cur = '\0';
		else
			*(end - 1) = '\0';
	}

	return cur - str;
}

// A format string is converted to the actual string, which is then
// truncated to PRINT_STR_MAX before printing.
#define PRINT_STR_MAX    256

int vprints(const char *format, va_list ap)
{
	char buffer[PRINT_STR_MAX];
	int ret;

	ret = vsnprints(buffer, sizeof(buffer), format, ap);

	if (ret >= sizeof(buffer)) {
        	ret = PRINT_STR_MAX;
		buffer[PRINT_STR_MAX - 1] = '\0';
	}

	serial_out(buffer, ret);

	return ret;
}
