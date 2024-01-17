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
    uint8_t in_low_memory;
    uint8_t _reserved[7];
    uint32_t secrets_page;
    uint32_t caa_page;
    uint32_t cpuid_page;
    uint32_t prevalidated_count;
    IgvmParamBlockFwMem prevalidated[8];
} IgvmParamBlockFwInfo;

typedef struct {
    uint32_t param_area_size;
    uint32_t param_page_offset;
    uint32_t memory_map_offset;
    uint32_t guest_context_offset;
    uint32_t cpuid_page;
    uint32_t secrets_page;
    uint16_t debug_serial_port;
    uint16_t _reserved[3];
    IgvmParamBlockFwInfo firmware;
    uint32_t kernel_reserved_size;
    uint32_t kernel_size;
    uint64_t kernel_base;
    uint64_t vtom;
} IgvmParamBlock;

typedef enum {
    parameter_page_general = 0,
    parameter_page_memory_map,
    num_parameter_pages,
} ParameterPageIndex;

typedef struct _igvm_vhs {
    struct _igvm_vhs *next;
    IGVM_VHT header_type;
    uint32_t header_size;
    void *data;
} IGVM_VHS;

typedef struct _data_obj {
    struct _data_obj *next;
    void *data;
    uint64_t address;
    uint32_t size;
    uint16_t page_type;
    uint16_t data_type;
    uint32_t page_data_flags;
    IGVM_VHS_PAGE_DATA *page_data_headers;
} DATA_OBJ;

typedef struct {
    IgvmParamBlockFwInfo fw_info;
    uint64_t vtom;
    DATA_OBJ *guest_context;
} FirmwareIgvmInfo;

IGVM_VHS *allocate_var_headers(
    IGVM_VHT header_type,
    uint32_t struct_size,
    uint32_t header_size,
    int count);

DATA_OBJ *construct_empty_data_object(uint64_t address, uint32_t size, const char *description);
DATA_OBJ *construct_mem_data_object(uint64_t address, uint32_t size, const char *description);

int read_hyperv_igvm_file(const char *file_name, FirmwareIgvmInfo *fw_info);

int parse_ovmf_metadata(const char *ovmf_filename, IgvmParamBlock *params);
