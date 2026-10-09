/* SPDX-License-Identifier: MIT */

#include <time.h>
#include <errno.h>

char *__utc = "UTC";

struct tm *gmtime_r(const time_t *restrict t, struct tm *restrict tm)
{
	if (__secs_to_tm(*t, tm) < 0) {
		errno = EOVERFLOW;
		return 0;
	}
	tm->tm_isdst = 0;
	tm->tm_gmtoff = 0;
	tm->tm_zone = __utc;
	return tm;
}


struct tm *gmtime(const time_t *t)
{
	static struct tm tm;
	return gmtime_r(t, &tm);
}
