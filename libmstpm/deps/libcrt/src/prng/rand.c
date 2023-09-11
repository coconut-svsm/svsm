/* SPDX-License-Identifier: MIT */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

/*
 * In the AMD64 Programmer's Manual Volume 3, the RDRAND and RDRAND
 * instructions suggests that software should implement a retry limit
 * to ensure forward progress of code.
 */
const uint32_t RDSEED_RETRIES = 1024;
const uint32_t RDRAND_RETRIES = 1024;

static uint64_t seed;

void srand(unsigned s)
{
	seed = s - 1;
}

static inline int rdrand32(uint32_t *rnd)
{
    unsigned char ok;

    __asm__ volatile("rdrand %0; setc %1":"=r"(*rnd), "=qm"(ok));
    if (!ok) {
        uint32_t retry = 0;
	while (retry < RDRAND_RETRIES) {
            __asm__ volatile("rdrand %0; setc %1":"=r"(*rnd), "=qm"(ok));
            if (ok)
		goto rc_success;
            retry++;
        }
        printf("%s: failed %d times\n", __func__, retry);
        return -1;
    }

rc_success:
    return 0;
}

static inline int rdseed32(uint32_t *rnd)
{
    unsigned char ok;

    __asm__ volatile("rdseed %0; setc %1":"=r"(*rnd), "=qm"(ok));
    if (!ok) {
        uint32_t retry = 0;
	while (retry < RDSEED_RETRIES) {
            __asm__ volatile("rdseed %0; setc %1":"=r"(*rnd), "=qm"(ok));
            if (ok)
		goto rc_success;
            retry++;
        }
        printf("%s: failed %d times\n", __func__, retry);
        return -1;
    }

rc_success:
    return 0;
}

int rand(void)
{
  uint32_t r = 0;
  if (rdrand32(&r)) {
     if (rdseed32(&r)) {
         printf("ERROR: %s: RDRAND and RDSEED failed reaching the retry count\n", __func__);
         abort();
     }
  }
  return r;
}
