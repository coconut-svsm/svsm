// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

#include <stdio.h>

struct cpuid_result {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
};

static void cpuid(unsigned int fn, struct cpuid_result *result)
{
    asm volatile("cpuid"
            : "=a" (result->eax), "=b" (result->ebx), "=c" (result->ecx), "=d" (result->edx) : "0" (fn) : "memory");
}

int main() {
    struct cpuid_result r;
    unsigned int bit;

    cpuid(0x80000000, &r);
    if (r.eax < 0x8000001f)
        return 1;

    cpuid(0x8000001f, &r);

    if ((r.eax & 2) == 0)
        return 1;

    bit = r.ebx & (64 - 1);

    printf("%d\n", bit);

    return 0;
}
