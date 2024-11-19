/* SPDX-License-Identifier: MIT */

#include <time.h>
#include <stdio.h>
#include <sys/types.h>

// Calls the rdtsc instruction to read the current value of the processor's
// time-stamp counter (a 64-bit MSR)
clock_t clock(void) {
	return rdtsc();
}

uint64_t secs;

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	(void) clk_id;
	if (tp) {
		tp->tv_nsec = rdtsc();
		tp->tv_sec = secs++;
	}
	return 0;
}

//  time() returns the time as the number of seconds since the Epoch
time_t time(time_t *tloc) {
	(void)tloc;
	time_t t = rdtsc();
	return t;
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz)
{
        if (!tv) return 0;
        tv->tv_sec = clock();
        tv->tv_usec = 0;
        return 0;
}
