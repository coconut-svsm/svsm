// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "sev-snp.h"
#include "igvm_defs.h"

#define PAGE_SIZE 0x1000

#define FIELD_OFFSET(type, field) ((int)((uint8_t *)&((type *)NULL)->field - (uint8_t *)NULL))

typedef struct {
    uint32_t base;
    uint32_t size;
} IgvmParamBlockFwMem;

typedef struct {
    uint32_t start;
    uint32_t size;
    uint32_t _reserved;
    uint32_t secrets_page;
    uint32_t caa_page;
    uint32_t cpuid_page;
    uint32_t reset_addr;
    uint32_t prevalidated_count;
    IgvmParamBlockFwMem prevalidated[8];
} IgvmParamBlockFwInfo;

typedef struct {
    uint32_t param_area_size;
    uint32_t param_page_offset;
    uint32_t memory_map_offset;
    uint32_t cpuid_page;
    uint32_t secrets_page;
    uint16_t debug_serial_port;
    uint16_t _reserved;
    IgvmParamBlockFwInfo firmware;
    uint32_t kernel_reserved_size;
    uint32_t kernel_size;
    uint64_t kernel_base;
} IgvmParamBlock;

int parse_ovmf_metadata(const char *ovmf_filename, IgvmParamBlock *params);
