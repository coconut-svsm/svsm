// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <byteswap.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

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

#define OVMF_TABLE_FOOTER_GUID		"96b582de-1fb2-45f7-baea-a366c55a082d"
#define OVMF_SEV_META_DATA_GUID		"dc886566-984a-4798-a75e-5585a7bf67cc"
#define SEV_INFO_BLOCK_GUID		"00f771de-1a7e-4fcb-890e-68c77e2fb44e"
#define SEV_HASH_TABLE_RV_GUID		"7255371f-3a3b-4b04-927b-1da6efa8d454"
#define SEV_SECRET_GUID			"4c2eb361-7d9b-4cc3-8081-127c90d3d294"
#define SEV_SNP_BOOT_BLOCK_GUID		"bd39c0c2-2f8e-4243-83e8-1b74cebcb7d9"
#define SVSM_INFO_GUID			"a789a612-0597-4c4b-a49f-cbb1fe9d1ddd"

struct __attribute__((__packed__)) snp_boot_block {
    /* Prevalidate range address */
    uint32_t pre_validated_start;
    uint32_t pre_validated_end;
    /* Secrets page address */
    uint32_t secrets_addr;
    uint32_t secrets_len;
    /* CPUID page address */
    uint32_t cpuid_addr;
    uint32_t cpuid_len;
};

struct __attribute__((__packed__)) sev_secret {
	uint32_t base;
	uint32_t size;
};

enum meta_data_type {
	SEV_DESC_TYPE_UNDEF,
	SEV_DESC_TYPE_SNP_SEC_MEM,
	SEV_DESC_TYPE_SNP_SECRETS,
	SEV_DESC_TYPE_CPUID,
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

struct __attribute__((__packed__)) svsm_info_block {
	uint32_t launch_offset;
};

#define META_SIZE	256

struct meta_buffer {
	char buffer[META_SIZE];
	uint16_t *len;
	char *end;
};

void init_buffer(struct meta_buffer *meta)
{
	struct UUID uuid;
	char *ptr;
	uint16_t *len;

	memset(meta->buffer, 0, META_SIZE);

	uuid_parse(OVMF_TABLE_FOOTER_GUID, &uuid);
	uuid = uuid_bswap(uuid);
	ptr = meta->buffer + META_SIZE - sizeof(uuid);

	memcpy(ptr, &uuid, sizeof(uuid));

	len  = (uint16_t *)(ptr - sizeof(*len));
	*len = sizeof(uuid) + sizeof(*len);

	meta->len = len;
	meta->end = (char *)len;
}

void add_table(struct meta_buffer *meta, const char *uuid_str, char *table, uint16_t size)
{
	struct UUID uuid;
	char *ptr;
	uint16_t *len;

	uuid_parse(uuid_str, &uuid);
	uuid = uuid_bswap(uuid);

	ptr = meta->end - sizeof(uuid);
	memcpy(ptr, &uuid, sizeof(uuid));

	len  = (uint16_t *)(ptr - sizeof(uint16_t));
	*len = size + sizeof(uuid) + sizeof(uint16_t);

	meta->end = (char *)len - size;
	memcpy(meta->end, table, size);

	*meta->len += *len;
}

#define NUM_DESCS	4
struct __attribute__((__packed__)) svsm_meta_data {
	char sig[4];
	uint32_t len;
	uint32_t version;
	uint32_t num_desc;
	struct meta_data_desc descs[NUM_DESCS];
};

void init_sev_meta(struct svsm_meta_data *svsm_meta)
{
	svsm_meta->sig[0]   = 'A';
	svsm_meta->sig[1]   = 'S';
	svsm_meta->sig[2]   = 'E';
	svsm_meta->sig[3]   = 'V';
	svsm_meta->len      = sizeof(*svsm_meta);
	svsm_meta->version  = 1;
	svsm_meta->num_desc = NUM_DESCS;

	svsm_meta->descs[0].base = 0x800000;
	svsm_meta->descs[0].len  = 0x6000;
	svsm_meta->descs[0].type = SEV_DESC_TYPE_SNP_SEC_MEM;

	svsm_meta->descs[1].base = 0x806000;
	svsm_meta->descs[1].len  = 0x1000;
	svsm_meta->descs[1].type = SEV_DESC_TYPE_SNP_SECRETS;

	svsm_meta->descs[2].base = 0x807000;
	svsm_meta->descs[2].len  = 0x1000;
	svsm_meta->descs[2].type = SEV_DESC_TYPE_CPUID;

	svsm_meta->descs[3].base = 0x808000;
	svsm_meta->descs[3].len  = 0x8D0000 - 0x808000;
	svsm_meta->descs[3].type = SEV_DESC_TYPE_SNP_SEC_MEM;
}

uint16_t meta_data_table_size(void)
{
	return sizeof(uint32_t) + sizeof(uint16_t) + sizeof(struct UUID);
}

void fill_buffer(struct meta_buffer *meta)
{
	uint32_t reset_ip = 0xfffffff0;
	uint32_t meta_offset;
	struct sev_secret secret;
	struct svsm_meta_data sev_meta;
#if 0
	struct snp_boot_block boot_block;
#endif
	struct svsm_info_block svsm_info;
	char *ptr;

	init_buffer(meta);

	add_table(meta, SEV_INFO_BLOCK_GUID, (char *)&reset_ip, sizeof(reset_ip));

	secret.base = 0xdeadbeef;
	secret.size = 0;
	add_table(meta, SEV_SECRET_GUID, (char *)&secret, sizeof(secret));

	svsm_info.launch_offset = 0;
	add_table(meta, SVSM_INFO_GUID, (char *)&svsm_info, sizeof(svsm_info));

	/* OVMF_SEV_META_DATA_GUID must be last entry */
	init_sev_meta(&sev_meta);
	meta_offset = ((meta->buffer + META_SIZE) - meta->end) + meta_data_table_size() + 32 + sizeof(sev_meta);
	add_table(meta, OVMF_SEV_META_DATA_GUID, (char *)&meta_offset, sizeof(meta_offset));

	/* Add metadata table */
	ptr = meta->end - sizeof(sev_meta);
	memcpy(ptr, &sev_meta, sizeof(sev_meta));
}

int main(int argc, char **argv)
{
	struct meta_buffer meta;
	int fd;

	fill_buffer(&meta);

	if (argc < 2) {
		printf("No filename given.\n");
		return 1;
	}

	fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		printf("Can't open file %s\n", argv[1]);
		return 1;
	}

	if (write(fd, meta.buffer, META_SIZE) != META_SIZE)
		perror("write");

	close(fd);

	return 0;
}
