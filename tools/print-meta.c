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

void parse_secret_data(void *data)
{
	struct sev_secret *sec = data;

	printf("	SEV_SECRET_GUID base : 0x%08x size: 0x%08x\n", sec->base, sec->size);
}

void parse_sev_info_block(void *data)
{
	uint32_t *d = data;

	printf("	SEV_INFO_BLOCK_GUID reset_addr = 0x%08x\n", *d);
}

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

void parse_boot_block(void *data)
{
	struct snp_boot_block *bb = data;

	printf("	pre_validated_start : 0x%08x\n", bb->pre_validated_start);
	printf("	pre_validated_end   : 0x%08x\n", bb->pre_validated_end);
	printf("	secrets_addr        : 0x%08x\n", bb->secrets_addr);
	printf("	secrets_len         : 0x%08x\n", bb->secrets_len);
	printf("	cpuid_addr          : 0x%08x\n", bb->cpuid_addr);
	printf("	cpuid_len           : 0x%08x\n", bb->cpuid_len);
}

void parse_sev_meta_data(void *data, uint8_t *buffer, size_t size)
{
	uint32_t *d = data;
	struct sev_meta_data *meta;
	int i;

	printf("	OVMF_SEV_META_DATA_GUID offset = 0x%08x\n", *d);

	meta = (struct sev_meta_data *)(buffer + size - *d);
	printf("	MetaData Signature: %c%c%c%c\n", meta->sig[0], meta->sig[1],
							 meta->sig[2], meta->sig[3]);
	printf("	MetaData Length   : %u\n", meta->len);
	printf("	MetaData Version  : %u\n", meta->version);
	printf("	MetaData NumDesc  : %u\n", meta->num_desc);

	for (i = 0; i < meta->num_desc; ++i) {
		printf("\t\tType: %u Base: 0x%08x Length: %d\n",
			meta->descs[i].type, meta->descs[i].base, meta->descs[i].len);
	}
}

uint8_t *parse_inner_table(uint8_t *ptr, uint8_t *buffer, size_t size)
{
	struct UUID *entry_uuid, meta_uuid, info_uuid, hash_table_uuid, secret_uuid, boot_block_uuid;
	int len;
	void *data;

	entry_uuid = (struct UUID *)(ptr - sizeof(struct UUID));
	len = *(uint16_t *)(ptr - sizeof(struct UUID) - sizeof(uint16_t));
	data = (void*)(ptr - len);

	uuid_parse(OVMF_SEV_META_DATA_GUID, &meta_uuid);
	meta_uuid = uuid_bswap(meta_uuid);

	uuid_parse(SEV_INFO_BLOCK_GUID, &info_uuid);
	info_uuid = uuid_bswap(info_uuid);

	uuid_parse(SEV_HASH_TABLE_RV_GUID, &hash_table_uuid);
	hash_table_uuid = uuid_bswap(hash_table_uuid);

	uuid_parse(SEV_SECRET_GUID, &secret_uuid);
	secret_uuid = uuid_bswap(secret_uuid);

	uuid_parse(SEV_SNP_BOOT_BLOCK_GUID, &boot_block_uuid);
	boot_block_uuid = uuid_bswap(boot_block_uuid);

	if (!uuid_cmp(entry_uuid, &meta_uuid)) {
		printf("Found OVMF_SEV_META_DATA_GUID with length %d\n", len);
		parse_sev_meta_data(data, buffer, size);
	} else if (!uuid_cmp(entry_uuid, &info_uuid)) {
		printf("Found SEV_INFO_BLOCK_GUID     with length %d\n", len);
		parse_sev_info_block(data);
	} else if (!uuid_cmp(entry_uuid, &hash_table_uuid)) {
		printf("Found SEV_HASH_TABLE_RV_GUID  with length %d\n", len);
	} else if (!uuid_cmp(entry_uuid, &secret_uuid)) {
		printf("Found SEV_SECRET_GUID         with length %d\n", len);
		parse_secret_data(data);
	} else if (!uuid_cmp(entry_uuid, &boot_block_uuid)) {
		printf("Found SEV_SNP_BOOT_BLOCK_GUID with length %d\n", len);
		parse_boot_block(data);
	} else {
		printf("Found UNKNOWN table           with length %d\n", len);
	}

	return ptr - len;
}

void parse_table(uint8_t *buffer, size_t size)
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

	printf("Found OVMF_TABLE_FOOTER_GUID\n");
	ptr -= 2;

	table_size = (*(uint16_t*) ptr) - sizeof(struct UUID) - sizeof(uint16_t);
	printf("Table Size: %d\n", table_size);

	table_ptr = ptr;

	while (table_ptr > (ptr - table_size)) {
		table_ptr = parse_inner_table(table_ptr, buffer, size);
	}
}

int main(int argc, char **argv)
{
	struct stat statbuf;
	uint8_t *buffer;
	size_t size;
	int fd;

	if (argc < 2) {
		printf("No filename given.\n");
		return 1;
	}

	if (stat(argv[1], &statbuf)) {
		printf("stat() failed\n");
		return 1;
	}

	size = statbuf.st_size;
	buffer = malloc(size);
	if (!buffer) {
		printf("Can not allocate buffer\n");
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Can't open file %s\n", argv[1]);
		return 1;
	}

	if (read(fd, buffer, size) != size) {
		printf("Failed to read file\n");
		return 1;
	}

	close(fd);

	parse_table(buffer, size);

	return 0;
}
