// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
// Author: Roy Hopkins <roy.hopkins@suse.com>

#include "igvmbld.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <byteswap.h>

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-" \
    "%02hhx%02hhx-%02hhx%02hhx-" \
    "%02hhx%02hhx-" \
    "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"

struct UUID {
    union {
        unsigned char data[16];
        struct {
            /* Generated in BE endian, can be swapped with qemu_uuid_bswap. */
            uint32_t time_low;
            uint16_t time_mid;
            uint16_t time_high_and_version;
            uint8_t  clock_seq_and_reserved;
            uint8_t  clock_seq_low;
            uint8_t  node[6];
        } fields;
    };
};

void bswap16s(uint16_t *s)
{
    *s = bswap_16(*s);
}

void bswap32s(uint32_t *s)
{
    *s = bswap_32(*s);
}

struct UUID uuid_bswap(struct UUID uuid)
{
    bswap32s(&uuid.fields.time_low);
    bswap16s(&uuid.fields.time_mid);
    bswap16s(&uuid.fields.time_high_and_version);
    return uuid;
}

int uuid_parse(const char *str, struct UUID *uuid)
{
    unsigned char *uu = &uuid->data[0];
    int ret;

    ret = sscanf(str, UUID_FMT, &uu[0], &uu[1], &uu[2], &uu[3],
            &uu[4], &uu[5], &uu[6], &uu[7], &uu[8], &uu[9],
            &uu[10], &uu[11], &uu[12], &uu[13], &uu[14],
            &uu[15]);

    if (ret != 16) {
        return -1;
    }
    return 0;
}

int uuid_cmp(const struct UUID *u1, const struct UUID *u2)
{
    return memcmp(u1, u2, sizeof(*u1));
}

#define OVMF_TABLE_FOOTER_GUID     "96b582de-1fb2-45f7-baea-a366c55a082d"
#define OVMF_SEV_META_DATA_GUID    "dc886566-984a-4798-a75e-5585a7bf67cc"

#define SEV_META_DESC_TYPE_MEM     1
#define SEV_META_DESC_TYPE_SECRETS 2
#define SEV_META_DESC_TYPE_CPUID   3
#define SEV_META_DESC_TYPE_CAA     4

enum meta_data_type {
    SEV_DESC_TYPE_UNDEF,
    SEV_DESC_TYPE_SNP_SEC_MEM,
    SEV_DESC_TYPE_SNP_SECRETS,
    SEV_DESC_TYPE_CPUID,
    SEV_DESC_TYPE_CAA
};

struct __attribute__((__packed__)) meta_data_desc {
    uint32_t base;
    uint32_t len;
    uint32_t type;
};

struct __attribute__((__packed__)) sev_meta_data {
    char sig[4];
    uint32_t len;
    uint32_t version;
    uint32_t num_desc;
    struct meta_data_desc descs[];
};

static void parse_sev_meta_data(void *data, uint8_t *buffer, size_t size, IgvmParamBlock *params)
{
    uint32_t *d = data;
    struct sev_meta_data *meta;
    int i;

    meta = (struct sev_meta_data *)(buffer + size - *d);

    for (i = 0; i < meta->num_desc; ++i) 
    {
        switch (meta->descs[i].type) 
        {
            case SEV_DESC_TYPE_SNP_SEC_MEM:
            {
                uint32_t entry = params->firmware.prevalidated_count;
                uint32_t max_entries = sizeof(params->firmware.prevalidated) / sizeof(IgvmParamBlockFwMem);
                if (entry == max_entries)
                {
                    fprintf(stderr, "OVMF metadata defines too many memory regions\n");
                    exit(1);
                }
                params->firmware.prevalidated[entry].base = meta->descs[i].base;
                params->firmware.prevalidated[entry].size = meta->descs[i].len;
                ++params->firmware.prevalidated_count;
                break;
            }

            case SEV_DESC_TYPE_SNP_SECRETS:
                params->firmware.secrets_page = meta->descs[i].base;
                break;

            case SEV_DESC_TYPE_CPUID:
                params->firmware.cpuid_page = meta->descs[i].base;
                break;

            case SEV_DESC_TYPE_CAA:
                params->firmware.caa_page = meta->descs[i].base;
                break;
        }
    }
}

static uint8_t *parse_inner_table(uint8_t *ptr, uint8_t *buffer, size_t size, IgvmParamBlock *params)
{
    struct UUID *entry_uuid, meta_uuid;
    int len;
    void *data;

    entry_uuid = (struct UUID *)(ptr - sizeof(struct UUID));
    len = *(uint16_t *)(ptr - sizeof(struct UUID) - sizeof(uint16_t));
    data = (void*)(ptr - len);

    uuid_parse(OVMF_SEV_META_DATA_GUID, &meta_uuid);
    meta_uuid = uuid_bswap(meta_uuid);

    if (!uuid_cmp(entry_uuid, &meta_uuid)) {
        parse_sev_meta_data(data, buffer, size, params);
    }
    return ptr - len;
}

static void parse_table(uint8_t *buffer, size_t size, IgvmParamBlock *params)
{
    struct UUID uuid;
    uint8_t *ptr;
    int table_size;
    uint8_t *table_ptr;

    uuid_parse(OVMF_TABLE_FOOTER_GUID, &uuid);
    uuid = uuid_bswap(uuid);
    ptr = buffer + size - 48;

    if (uuid_cmp((struct UUID *)ptr, &uuid))
        return;

    ptr -= 2;
    table_size = (*(uint16_t*) ptr) - sizeof(struct UUID) - sizeof(uint16_t);
    table_ptr = ptr;

    while (table_ptr > (ptr - table_size)) {
        table_ptr = parse_inner_table(table_ptr, buffer, size, params);
    }
}

int parse_ovmf_metadata(const char *ovmf_filename, IgvmParamBlock *params)
{
    struct stat statbuf;
    uint8_t *buffer;
    size_t size;
    int fd;

    if (stat(ovmf_filename, &statbuf)) {
        fprintf(stderr, "stat() failed\n");
        return 1;
    }

    size = statbuf.st_size;
    buffer = malloc(size);
    if (!buffer) {
        fprintf(stderr, "Cannot allocate buffer\n");
        return 1;
    }

    fd = open(ovmf_filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Can't open file %s\n", ovmf_filename);
        return 1;
    }

    if (read(fd, buffer, size) != size) {
        fprintf(stderr, "Failed to read file\n");
        return 1;
    }

    close(fd);

    parse_table(buffer, size, params);

    return 0;
}
