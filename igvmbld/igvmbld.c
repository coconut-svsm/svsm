// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)
//
// This module is provided in C as a bootstrapper to permit generation of IGVM
// files pending creation of a Rust version.  The C version should be
// maintained until the Rust version is ready.
//

#include "igvmbld.h"

typedef struct {
    uint32_t cpu_count;
    uint32_t environment_info;
} IgvmParamPage;

typedef struct {
    uint32_t kernel_start;
    uint32_t kernel_end;
    uint32_t filesystem_start;
    uint32_t filesystem_end;
    uint32_t igvm_param_block;
    uint32_t reserved;
} Stage2Stack;

typedef struct _param_page {
    struct _param_page *next;
    uint32_t address;
    ParameterPageIndex index;
} PARAM_PAGE;

const char *stage2_filename;
const char *kernel_filename;
const char *filesystem_filename;
const char *output_filename;
const char *fw_filename;
uint32_t fw_size;
uint32_t fw_base;
int is_qemu;
int is_hyperv;
int com_port = 1;
int is_verbose;

const uint16_t com_io_ports[] = { 0x3f8, 0x2f8, 0x3e8, 0x2e8 };

DATA_OBJ *data_object_list;
PARAM_PAGE *param_page_list;

IGVM_VHS *first_var_hdr;
IGVM_VHS **last_var_hdr;
uint32_t var_hdr_offset;
uint32_t total_file_size;

static uint32_t _crc;

static void crc32b_init() {
    _crc = 0xffffffff;
}

static void crc32b_update(uint8_t *message, uint32_t len) {
   uint32_t i;
   int32_t j;
   uint32_t byte, mask;

   for (i = 0; i < len; ++i) {
      byte = message[i];
      _crc = _crc ^ byte;
      for (j = 7; j >= 0; --j) {
         mask = 0 - (_crc & 1);
         _crc = (_crc >> 1) ^ (0xedb88320 & mask);
      }
   }
}

static uint32_t crc32b_finish() {
   return ~_crc;
}

void construct_parameter_page(uint32_t address, ParameterPageIndex index, const char *description)
{
    PARAM_PAGE *param_page;

    if (is_verbose)
    {
        printf("%08X-%08X: \"%s\" parameter page\n", address, address + 0x1000, description);
    }

    param_page = malloc(sizeof(PARAM_PAGE));
    param_page->address = address;
    param_page->index = index;
    param_page->next = param_page_list;
    param_page_list = param_page;
}

DATA_OBJ *insert_data_object(DATA_OBJ *data_object)
{
    data_object->next = data_object_list;
    data_object_list = data_object;
    return data_object;
}

DATA_OBJ *allocate_data_object(uint64_t address, uint32_t size, uint32_t data_size)
{
    uint32_t allocation_size;
    DATA_OBJ *data_object;

    data_object = malloc(sizeof(DATA_OBJ));
    data_object->address = address;
    data_object->size = size;
    if (data_size != 0)
    {
        // Make sure the allocation is rounded up to a page boundary because
        // the data will be written in multiples of pages.
        allocation_size = (data_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        data_object->data = malloc(allocation_size);

        // Zero-initialize any allocation padding to sure that it is zero in
        // the final file.
        if (allocation_size != data_size)
        {
            memset((uint8_t *)data_object->data + data_size, 0, allocation_size - data_size);
        }
    }
    else
        data_object->data = NULL;
    data_object->data_type = IGVM_VHT_PAGE_DATA;
    data_object->page_type = IgvmPageType_Normal;
    data_object->page_data_flags = 0;
    return data_object;
}

DATA_OBJ *construct_empty_data_object(uint64_t address, uint32_t size, const char *description)
{
    if (is_verbose)
    {
        printf("%08lX-%08lX: \"%s\" empty data\n", address, address + size, description);
    }
    return insert_data_object(allocate_data_object(address, size, 0));
}

DATA_OBJ *construct_mem_data_object(uint64_t address, uint32_t size, const char *description)
{
    if (is_verbose)
    {
        printf("%08lX-%08lX: \"%s\" mem data\n", address, address + size, description);
    }
    return insert_data_object(allocate_data_object(address, size, size));
}

DATA_OBJ *construct_file_data_object(
    const char *file_name,
    uint32_t address
    )
{
    DATA_OBJ *data_obj;
    FILE *file;
    int file_size;

    file = fopen(file_name, "r");
    if (file == NULL)
    {
        fprintf(stderr, "could not open %s\n", file_name);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
ReadError:
        fprintf(stderr, "could not read %s\n", file_name);
        fclose(file);
        return NULL;
    }

    file_size = ftell(file);

    data_obj = construct_mem_data_object(address, file_size, file_name);

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        goto ReadError;
    }
    if (fread(data_obj->data, 1, file_size, file) != file_size)
    {
        goto ReadError;
    }

    fclose(file);

    return data_obj;
}

uint32_t var_header_file_size(IGVM_VHS *header)
{
    uint32_t pad_size;

    // Variable headers must start on an 8-byte boundary but individual
    // headers are only required to be aligned to 4-byte boundaries.
    pad_size = header->header_size & 7;
    if (pad_size != 0)
    {
        pad_size = 8 - pad_size;
    }

    return header->header_size + pad_size;
}

void add_var_header(IGVM_VHS *header)
{
    // Add this header to the chain of headers.
    *last_var_hdr = header;
    last_var_hdr = &header->next;

    // Account for the number of bytes taken up by this header.
    var_hdr_offset += 8 + var_header_file_size(header);
}

IGVM_VHS *allocate_var_headers(
    IGVM_VHT header_type,
    uint32_t struct_size,
    uint32_t header_size,
    int count)
{
    uint8_t *data;
    IGVM_VHS *headers;
    int i;

    // Round the size up to a 32-bit boundary.
    header_size = (header_size + 3) & ~3;

    // Allocate a data block to hold all of the header contents.
    data = malloc(struct_size * count);

    // Allocate a single array to hold all requested headers.
    headers = malloc(count * sizeof(IGVM_VHS));
    headers->data = data;

    // Initialize each header structure with the appropriate portion of the
    // data block and add it to the chain of headers.
    for (i = 0; i < count; ++i)
    {
        headers[i].header_type = header_type;
        headers[i].header_size = header_size;
        headers[i].data = data;
        add_var_header(&headers[i]);

        data += struct_size;
    }

    return headers;
}

void fill_cpuid_page(SNP_CPUID_PAGE *cpuid_page)
{
    int i;

    memset(cpuid_page, 0, PAGE_SIZE);
    i = 0;

    // Lead off with the extended SEV features leaf to simplify searches.
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001F;
    cpuid_page->CpuidInfo[i].EcxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 2;
    cpuid_page->CpuidInfo[i++].EaxIn = 4;
    cpuid_page->CpuidInfo[i].EcxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 4;
    cpuid_page->CpuidInfo[i].EcxIn = 2;
    cpuid_page->CpuidInfo[i++].EaxIn = 4;
    cpuid_page->CpuidInfo[i].EcxIn = 3;
    cpuid_page->CpuidInfo[i++].EaxIn = 4;
    cpuid_page->CpuidInfo[i++].EaxIn = 5;
    cpuid_page->CpuidInfo[i++].EaxIn = 6;
    cpuid_page->CpuidInfo[i++].EaxIn = 7;
    cpuid_page->CpuidInfo[i].EcxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 7;
    cpuid_page->CpuidInfo[i++].EaxIn = 11;
    cpuid_page->CpuidInfo[i].EcxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 11;
    cpuid_page->CpuidInfo[i++].EaxIn = 13;
    cpuid_page->CpuidInfo[i].EcxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 13;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000001;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000002;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000003;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000004;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000005;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000006;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000007;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000008;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000000A;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x80000019;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001A;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001D;
    cpuid_page->CpuidInfo[i].EcxIn = 1;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001D;
    cpuid_page->CpuidInfo[i].EcxIn = 2;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001D;
    cpuid_page->CpuidInfo[i].EcxIn = 3;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001D;
    cpuid_page->CpuidInfo[i++].EaxIn = 0x8000001E;
    cpuid_page->Count = i;
}

void generate_initial_vmsa(SEV_VMSA *vmsa)
{
    memset(vmsa, 0, PAGE_SIZE);

    // Establish CS as a 32-bit code selector.
    vmsa->segments[SevSegment_Cs].attributes = 0xC9B;
    vmsa->segments[SevSegment_Cs].limit = 0xFFFFFFFF;
    vmsa->segments[SevSegment_Cs].selector = 0x08;

    // Establish all data segments as generic data selectors.
    vmsa->segments[SevSegment_Ds].attributes = 0xA93;
    vmsa->segments[SevSegment_Ds].limit = 0xFFFFFFFF;
    vmsa->segments[SevSegment_Ds].selector = 0x10;
    vmsa->segments[SevSegment_Ss] = vmsa->segments[SevSegment_Ds];
    vmsa->segments[SevSegment_Ss].selector = 0x10;
    vmsa->segments[SevSegment_Es] = vmsa->segments[SevSegment_Ds];
    vmsa->segments[SevSegment_Es].selector = 0x10;
    vmsa->segments[SevSegment_Fs] = vmsa->segments[SevSegment_Ds];
    vmsa->segments[SevSegment_Fs].selector = 0x10;
    vmsa->segments[SevSegment_Gs] = vmsa->segments[SevSegment_Ds];
    vmsa->segments[SevSegment_Gs].selector = 0x10;

    // EFER.SVME.
    vmsa->efer = 0x1000;

    // CR0.PE | CR0.NE.
    vmsa->cr0 = 0x21;

    // CR4.MCE.
    vmsa->cr4 = 0x40;

    vmsa->guest_pat = 0x0007040600070406;
    vmsa->xcr0 = 1;
    vmsa->rflags = 2;
    vmsa->rip = 0x10000;
    vmsa->rsp = vmsa->rip - sizeof(Stage2Stack);

    vmsa->sev_features = SevFeature_Snp | SevFeature_RestrictInj;
}

IGVM_VHS_SUPPORTED_PLATFORM *setup_igvm_platform_header(void)
{
    IGVM_VHS *header;
    IGVM_VHS_SUPPORTED_PLATFORM *platform;

    // Configure a platform header for SEV-SNP.
    header = allocate_var_headers(
        IGVM_VHT_SUPPORTED_PLATFORM,
        sizeof(IGVM_VHS_SUPPORTED_PLATFORM),
        sizeof(IGVM_VHS_SUPPORTED_PLATFORM),
        1);
    platform = header->data;
    memset(platform, 0, sizeof(IGVM_VHS_SUPPORTED_PLATFORM));

    // Choose the low bit to decsribe the only platform supported by this
    // file.
    platform->CompatibilityMask = 1;
    platform->HighestVtl = 2;
    platform->PlatformType = IgvmPlatformType_SevSnp;
    platform->PlatformVersion = 1;

    return platform;
}

void generate_required_memory_header(IgvmParamBlock *igvm_parameter_block)
{
    IGVM_VHS *header;
    IGVM_VHS_REQUIRED_MEMORY *required_memory;

    header = allocate_var_headers(
        IGVM_VHT_REQUIRED_MEMORY,
        sizeof(IGVM_VHS_REQUIRED_MEMORY),
        sizeof(IGVM_VHS_REQUIRED_MEMORY),
        1);
    required_memory = header->data;
    memset(required_memory, 0, sizeof(IGVM_VHS_REQUIRED_MEMORY));

    required_memory->GPA = igvm_parameter_block->kernel_base;
    required_memory->CompatibilityMask = 1;
    required_memory->NumberOfBytes = igvm_parameter_block->kernel_size;
}

IGVM_VHS_PARAMETER *generate_parameter_header(IGVM_VHT header_type)
{
    IGVM_VHS *header;

    header = allocate_var_headers(
        header_type,
        sizeof(IGVM_VHS_PARAMETER),
        sizeof(IGVM_VHS_PARAMETER),
        1);
    return header->data;
}

void generate_parameter_headers(void)
{
    IGVM_VHS *header;
    PARAM_PAGE *param_page;
    IGVM_VHS_PARAMETER *parameter;
    IGVM_VHS_PARAMETER_AREA *parameter_area;
    IGVM_VHS_PARAMETER_INSERT *parameter_insert;

    // Generate a parameter area header for each parameter page.  Each
    // parameter area is exactly one page and contains no initial data.
    param_page = param_page_list;
    while (param_page != NULL)
    {
        header = allocate_var_headers(
            IGVM_VHT_PARAMETER_AREA,
            sizeof(IGVM_VHS_PARAMETER_AREA),
            sizeof(IGVM_VHS_PARAMETER_AREA),
            1);
        parameter_area = header->data;
        parameter_area->FileOffset = 0;
        parameter_area->NumberOfBytes = PAGE_SIZE;
        parameter_area->ParameterPageIndex = param_page->index;
        param_page = param_page->next;
    }

    // Insert parameter elements for the required parameters.  This will cause
    // the loader to populate the parameter areas.
    parameter = generate_parameter_header(IGVM_VHT_VP_COUNT_PARMETER);
    parameter->ByteOffset = FIELD_OFFSET(IgvmParamPage, cpu_count);
    parameter->ParameterPageIndex = parameter_page_general;

    parameter = generate_parameter_header(IGVM_VHT_ENVIRONMENT_INFO_PARAMETER);
    parameter->ByteOffset = FIELD_OFFSET(IgvmParamPage, environment_info);
    parameter->ParameterPageIndex = parameter_page_general;

    parameter = generate_parameter_header(IGVM_VHT_MEMORY_MAP);
    parameter->ByteOffset = 0;
    parameter->ParameterPageIndex = parameter_page_memory_map;

    // Place the populated parameter areas into the guest address space.
    param_page = param_page_list;
    while (param_page != NULL)
    {
        header = allocate_var_headers(
            IGVM_VHT_PARAMETER_INSERT,
            sizeof(IGVM_VHS_PARAMETER_INSERT),
            sizeof(IGVM_VHS_PARAMETER_INSERT),
            1);
        parameter_insert = header->data;
        parameter_insert->CompatibilityMask = 1;
        parameter_insert->GPA = param_page->address;
        parameter_insert->ParameterPageIndex = param_page->index;
        param_page = param_page->next;
    }
}

void generate_data_headers(void)
{
    uint64_t address;
    DATA_OBJ *data_obj;
    IGVM_VHS *headers;
    uint32_t header_size;
    uint32_t i;
    uint32_t page_count;
    IGVM_VHS_PAGE_DATA *page_data;
    uint32_t struct_size;

    // For each data block, allocate an array of data headers to describe the
    // data.
    data_obj = data_object_list;
    while (data_obj != NULL)
    {
        page_count = (data_obj->size + PAGE_SIZE - 1) / PAGE_SIZE;
        if (data_obj->data_type == IGVM_VHT_VP_CONTEXT)
        {
            struct_size = sizeof(IGVM_VHS_VP_CONTEXT);
            // Do not include the compiler-generated padding to a multiple
            // of 64 bits - only 32-bit alignment is expected in the file.
            header_size = FIELD_OFFSET(IGVM_VHS_VP_CONTEXT, padding);
        }
        else
        {
            struct_size = sizeof(IGVM_VHS_PAGE_DATA);
            header_size = struct_size;
        }
        headers = allocate_var_headers(
            data_obj->data_type,
            struct_size,
            header_size,
            page_count);
        page_data = headers->data;
        data_obj->page_data_headers = page_data;
        memset(page_data, 0, page_count * header_size);

        // Populate each data header with the correct GPA.  The file offsets
        // will be filled in later.  Since a VP context is only a single page,
        // and since the first 16 bytes of the VP context structure align with
        // the page data structure, this loop is safe for both types.
        address = data_obj->address;
        for (i = 0; i < page_count; ++i)
        {
            page_data[i].GPA = address;
            page_data[i].CompatibilityMask = 1;
            page_data[i].Flags = data_obj->page_data_flags;
            address += PAGE_SIZE;            
        }

        if (data_obj->data_type != IGVM_VHT_VP_CONTEXT)
        {
            for (i = 0; i < page_count; ++i)
            {
                page_data[i].DataType = data_obj->page_type;
            }
        }

        data_obj = data_obj->next;
    }
}

void assign_file_data(void)
{
    IGVM_VHS_PAGE_DATA *data_headers;
    DATA_OBJ *data_obj;
    uint32_t file_offset;
    uint32_t i;
    uint32_t page_count;

    // Round the file offset up to a page boundary.
    file_offset = (var_hdr_offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    // Assign a file offset to each data page.
    data_obj = data_object_list;
    while (data_obj != NULL)
    {
        if (data_obj->data != NULL)
        {
            page_count = (data_obj->size + PAGE_SIZE - 1) / PAGE_SIZE;
            data_headers = data_obj->page_data_headers;

            // Since a VP context is only a single page, and since the first
            // 16 bytes of the VP context structure align with the page data
            // structure, this loop is safe for both types.
            for (i = 0; i < page_count; ++i)
            {
                data_headers[i].FileOffset = file_offset;
                file_offset += PAGE_SIZE;
            }
        }

        data_obj = data_obj->next;
    }

    total_file_size = file_offset;
}

int generate_igvm_file(const char *filename)
{
    uint8_t *data;
    IGVM_VHS_PAGE_DATA *data_headers;
    DATA_OBJ *data_obj;
    FILE *file;
    IGVM_FIXED_HEADER fixed_header;
    IGVM_VHS *header;
    uint32_t i;
    uint32_t pad;
    uint32_t pad_size;
    uint32_t page_count;
    IGVM_VAR_HEADER var_header;
    uint32_t crc32;

    pad = 0;

    crc32b_init();

    file = fopen(filename, "w");
    if (file == NULL)
    {
        fprintf(stderr, "could not create %s\n", filename);
        return 1;
    }

    // Write the fixed header first.
    memset(&fixed_header, 0, sizeof(IGVM_FIXED_HEADER));
    fixed_header.Magic = (uint32_t)IGVM_MAGIC;
    fixed_header.FormatVersion = 1;
    fixed_header.VariableHeaderOffset = sizeof(IGVM_FIXED_HEADER);
    fixed_header.VariableHeaderSize = var_hdr_offset - fixed_header.VariableHeaderOffset;
    fixed_header.TotalFileSize = total_file_size;

    crc32b_update((uint8_t *)&fixed_header, sizeof(IGVM_FIXED_HEADER));

    if (fwrite(&fixed_header, sizeof(IGVM_FIXED_HEADER), 1, file) != 1)
    {
WriteError:
        fprintf(stderr, "could not write %s\n", filename);
        fclose(file);
        unlink(filename);
        return 1;
    }

    // Write each variable header.
    *last_var_hdr = NULL;
    header = first_var_hdr;
    while (header != NULL)
    {
        var_header.header_type = header->header_type;
        var_header.header_size = header->header_size;
        if (fwrite(&var_header, sizeof(IGVM_VAR_HEADER), 1, file) != 1)
        {
            goto WriteError;
        }
        if (fwrite(header->data, header->header_size, 1, file) != 1)
        {
            goto WriteError;
        }
        crc32b_update((uint8_t *)&var_header, sizeof(IGVM_VAR_HEADER));
        crc32b_update((uint8_t *)header->data, header->header_size);

        pad_size = var_header_file_size(header) - header->header_size;
        if (pad_size != 0)
        {
            pad_size = 8 - pad_size;
            if (fwrite(&pad, 1, pad_size, file) != pad_size)
            {
                goto WriteError;
            }
            crc32b_update((uint8_t *)&pad, pad_size);
        }

        header = header->next;
    }

    // Write all file data.
    data_obj = data_object_list;
    while (data_obj != NULL)
    {
        if (data_obj->data != NULL)
        {
            page_count = (data_obj->size + PAGE_SIZE - 1) / PAGE_SIZE;
            data_headers = data_obj->page_data_headers;
            data = data_obj->data;
            for (i = 0; i < page_count; ++i)
            {
                if (fseek(file, data_headers[i].FileOffset, SEEK_SET) != 0)
                {
                    goto WriteError;
                }
                if (fwrite(data, 1, PAGE_SIZE, file) != PAGE_SIZE)
                {
                    goto WriteError;
                }
                data += PAGE_SIZE;
            }
        }

        data_obj = data_obj->next;
    }
    
    // Seek back and fill in the checksum.
    if (fseek(file, FIELD_OFFSET(IGVM_FIXED_HEADER, Checksum), SEEK_SET) != 0) {
        goto WriteError;
    }
    crc32 = crc32b_finish();
    if (fwrite(&crc32, 1, sizeof(crc32), file) != sizeof(crc32)) {
        goto WriteError;
    }

    fclose(file);
    return 0;
}

static int check_firmware_options() 
{
    if (is_qemu)
    {
        FILE *fp;

        if (!fw_filename)
        {
            // Firmware image is optional.
            return 0;
        }

        // Get the firmware file size so we can determine the top and bottom address
        // range.
        fp = fopen(fw_filename, "rb");
        if (!fp)
        {
            fprintf(stderr, "Firmware file cannot be opened: \"%s\"\n", fw_filename);
            return 1;
            
        }
        if (fseek(fp, 0, SEEK_END) != 0)
        {
            fprintf(stderr, "Failed to read firmware file: \"%s\"\n", fw_filename);
            fclose(fp);
            return 1;
        }
        fw_size = ftell(fp);
        fclose(fp);

        // OVMF firmware must be aligned with the top at 4GB.
        fw_base = 0xffffffff - fw_size + 1;
    }

    return 0;
}

int parse_options(int argc, const char *argv[])
{
    while (argc != 0)
    {
        if (0 == strcmp(argv[0], "--stage2"))
        {
            if (stage2_filename != NULL)
            {
                fprintf(stderr, "--stage2 specified more than once\n");
                return 1;
            }
            if (argc == 1)
            {
                fprintf(stderr, "missing argument for --stage2\n");
                return 1;
            }

            stage2_filename = argv[1];
            argc -= 1;
            argv += 1;
        }
        else if (0 == strcmp(argv[0], "--kernel"))
        {
            if (kernel_filename != NULL)
            {
                fprintf(stderr, "--kernel specified more than once\n");
                return 1;
            }
            if (argc == 1)
            {
                fprintf(stderr, "missing argument for --kernel\n");
                return 1;
            }

            kernel_filename = argv[1];
            argc -= 1;
            argv += 1;
        }
        else if (0 == strcmp(argv[0], "--filesystem"))
        {
            if (filesystem_filename != NULL)
            {
                fprintf(stderr, "--filesystem specified more than once\n");
                return 1;
            }
            if (argc == 1)
            {
                fprintf(stderr, "missing argument for --filesystem\n");
                return 1;
            }

            filesystem_filename = argv[1];
            argc -= 1;
            argv += 1;
        }
        else if (0 == strcmp(argv[0], "--output"))
        {
            if (output_filename != NULL)
            {
                fprintf(stderr, "--output specified more than once\n");
                return 1;
            }
            if (argc == 1)
            {
                fprintf(stderr, "missing argument for --output\n");
                return 1;
            }

            output_filename = argv[1];
            argc -= 1;
            argv += 1;
        }
        else if (0 == strcmp(argv[0], "--com-port"))
        {
            if (argc == 1)
            {
                fprintf(stderr, "missing argument for --com_port\n");
                return 1;
            }

            com_port = atoi(argv[1]);
            if (com_port < 1 || com_port > 4)
            {
                fprintf(stderr, "invalid argument for --com_port: %s\n", argv[1]);
                return 1;
            }
            argc -= 1;
            argv += 1;
        }
        else if (0 == strcmp(argv[0], "--qemu"))
        {
            is_qemu = 1;
        }
        else if (0 == strcmp(argv[0], "--hyperv"))
        {
            is_hyperv = 1;
        }
        else if ((0 == strcmp(argv[0], "--verbose")) || 
                 (0 == strcmp(argv[0], "-v")))
        {
            is_verbose = 1;
        }
        else if (0 == strcmp(argv[0], "--firmware"))
        {
            if (fw_filename != NULL)
            {
                fprintf(stderr, "--firmware specified more than once\n");
                return 1;
            }
            if (argc == 1)
            {
                fprintf(stderr, "missing argument for --firmware\n");
                return 1;
            }
            fw_filename = argv[1];
            argc -= 1;
            argv += 1;
        }
        else
        {
            fprintf(stderr, "unknown option %s\n", argv[0]);
            return 1;
        }

        argc -= 1;
        argv += 1;
    }

    if (stage2_filename == NULL)
    {
        fprintf(stderr, "missing stage 2 filename\n");
        return 1;
    }
    if (kernel_filename == NULL)
    {
        fprintf(stderr, "missing kernel filename\n");
        return 1;
    }
    if (output_filename == NULL)
    {
        fprintf(stderr, "missing output filename\n");
        return 1;
    }

    if (is_qemu + is_hyperv != 1)
    {
        fprintf(stderr, "exactly one of --qemu and --hyperv must be specified\n");
        return 1;
    }

    if (check_firmware_options() != 0) 
    {
        return 1;
    }

    return 0;
}

static void print_fw_metadata(IgvmParamBlock *igvm_parameter_block)
{
    uint32_t i;

    printf("  firmware:\n");
    printf("    start: 0x%X\n", igvm_parameter_block->firmware.start);
    printf("    size: 0x%X\n", igvm_parameter_block->firmware.size);
    printf("    secrets_page: 0x%X\n", igvm_parameter_block->firmware.secrets_page);
    printf("    caa_page: 0x%X\n", igvm_parameter_block->firmware.caa_page);
    printf("    cpuid_page: 0x%X\n", igvm_parameter_block->firmware.cpuid_page);
    printf("    prevalidated_count: 0x%X\n", igvm_parameter_block->firmware.prevalidated_count);
    for (i = 0; i < igvm_parameter_block->firmware.prevalidated_count; ++i)
    {
        printf("      prevalidated[%d].base: 0x%X\n", i, igvm_parameter_block->firmware.prevalidated[i].base);
        printf("      prevalidated[%d].size: 0x%X\n", i, igvm_parameter_block->firmware.prevalidated[i].size);
    }
}

static void print_param_block(IgvmParamBlock *igvm_parameter_block)
{
    printf("\nigvm_parameter_block:\n");
    printf("  param_area_size: 0x%X\n", igvm_parameter_block->param_area_size);
    printf("  param_page_offset: 0x%X\n", igvm_parameter_block->param_page_offset);
    printf("  memory_map_offset: 0x%X\n", igvm_parameter_block->memory_map_offset);
    printf("  guest_context_offset: 0x%X\n", igvm_parameter_block->guest_context_offset);
    printf("  cpuid_page: 0x%X\n", igvm_parameter_block->cpuid_page);
    printf("  secrets_page: 0x%X\n", igvm_parameter_block->secrets_page);
    printf("  debug_serial_port: 0x%X\n", igvm_parameter_block->debug_serial_port);
    printf("  _reserved[3]: %02X%02X%02X\n", igvm_parameter_block->_reserved[0], 
                                             igvm_parameter_block->_reserved[1], 
                                             igvm_parameter_block->_reserved[2]);
    print_fw_metadata(igvm_parameter_block);
    printf("  kernel_reserved_size: 0x%X\n", igvm_parameter_block->kernel_reserved_size);
    printf("  kernel_size: 0x%X\n", igvm_parameter_block->kernel_size);
    printf("  kernel_base: 0x%lX\n", igvm_parameter_block->kernel_base);
    printf("  vtom: 0x%lX\n", igvm_parameter_block->vtom);
}

int main(int argc, const char *argv[])
{
    uint32_t address;
    DATA_OBJ *cpuid_page;
    int err;
    DATA_OBJ *filesystem_data;
    FirmwareIgvmInfo fw_info;
    DATA_OBJ *igvm_parameter_object;
    IgvmParamBlock *igvm_parameter_block;
    DATA_OBJ *initial_stack;
    DATA_OBJ *kernel_data;
    IGVM_VHS_SUPPORTED_PLATFORM *platform;
    DATA_OBJ *secrets_page;
    DATA_OBJ *stage2_data;
    Stage2Stack *stage2_stack;
    uint64_t vmsa_address;
    DATA_OBJ *vmsa_data;

    err = parse_options(argc - 1, argv + 1);
    if (err != 0)
    {
        return err;
    }

    // Initialize an empty variable header list and set the variable header
    // offset to begin just after the fixed header.
    last_var_hdr = &first_var_hdr;
    var_hdr_offset = sizeof(IGVM_FIXED_HEADER);

    // Set up the platform compatibility header.
    platform = setup_igvm_platform_header();

    // Construct a set of ranges for the memory map:
    // 0x000000-0x00EFFF: zero-filled (must be pre-validated)
    // 0x00F000-0x00FFFF: initial stage 2 stack page
    // 0x010000-0x0nnnnn: stage 2 image
    // 0x0nnnnn-0x09DFFF: zero-filled (must be pre-validated)
    // 0x09E000-0x09EFFF: Secrets page
    // 0x09F000-0x09FFFF: CPUID page
    // 0x100000-0x1nnnnn: kernel
    // 0x1nnnnn-0x1nnnnn: filesystem
    // 0x1nnnnn-0x1nnnnn: IGVM parameter block
    // 0x1nnnnn-0x1nnnnn: general and memory map parameter pages
    // 0xFFnn0000-0xFFFFFFFF: OVMF firmware (QEMU only, if specified)
    construct_empty_data_object(0x00000, 0xF000, "Low memory");

    // Construct a page containing an initial stack.  This is the page
    // immediately below 64K, where stage 2 is loaded.
    initial_stack = construct_mem_data_object(0xF000, PAGE_SIZE, "Initial stack");

    // Construct a data object for the stage 2 image.  Stage 2 is always
    // loaded at 64K.
    stage2_data = construct_file_data_object(stage2_filename, 0x10000);
    if (stage2_data == NULL)
    {
        return 1;
    }

    address = (stage2_data->address + stage2_data->size + PAGE_SIZE - 1) &
              ~(PAGE_SIZE - 1);
    if (address > 0x9E000)
    {
        fprintf(stderr, "stage 2 image is too large\n");
        return 1;
    }
    else if (address < 0x9E000)
    {
        construct_empty_data_object(address, 0x9E000 - address, "Stage 2 free space");
    }

    // Allocate a page to hold the secrets page.  This is not considered part
    // of the IGVM data.
    secrets_page = construct_empty_data_object(0x9E000, PAGE_SIZE, "Secrets page");
    secrets_page->page_type = IgvmPageType_Secrets;

    cpuid_page = construct_mem_data_object(0x9F000, PAGE_SIZE, "CPUID page");
    cpuid_page->page_type = IgvmPageType_Cpuid;
    fill_cpuid_page((SNP_CPUID_PAGE *)cpuid_page->data);

    // Plan to load the kernel image at a base address of 1 MB unless it must
    // be relocated due to firmware.
    address = 1 << 20;

    memset(&fw_info, 0, sizeof(FirmwareIgvmInfo));

    // If a hyper-v firmware file was specified, then load it.
    if (is_hyperv)
    {
        if (fw_filename != NULL)
        {
            err = read_hyperv_igvm_file(fw_filename, &fw_info);
            if (err != 0)
            {
                return err;
            }

            address = fw_info.fw_info.start + fw_info.fw_info.size;
        }
    }

    // Construct a data object for the kernel.
    kernel_data = construct_file_data_object(kernel_filename, address);
    if (kernel_data == NULL)
    {
        return 1;
    }
    address = (kernel_data->address + kernel_data->size + PAGE_SIZE - 1) &
              ~(PAGE_SIZE - 1);    

    // If a filesystem image is present, then load it after the kernel.  It is
    // rounded up to the next page boundary to avoid overlapping with any of
    // the pages in the kernel data object.
    if (filesystem_filename != NULL)
    {
        filesystem_data = construct_file_data_object(filesystem_filename, address);
        if (filesystem_data == NULL)
        {
            return 1;
        }
        address = (filesystem_data->address + filesystem_data->size + PAGE_SIZE - 1) &
                  ~(PAGE_SIZE - 1);
    }
    else
    {
        filesystem_data = NULL;
    }

    // Construct the initial stack contents.
    stage2_stack = (Stage2Stack *)((uint8_t *)initial_stack->data + PAGE_SIZE) - 1;
    stage2_stack->kernel_start = (uint32_t)kernel_data->address;
    stage2_stack->kernel_end = (uint32_t)kernel_data->address + kernel_data->size;
    if (filesystem_data != NULL)
    {
        stage2_stack->filesystem_start = (uint32_t)filesystem_data->address;
        stage2_stack->filesystem_end = (uint32_t)filesystem_data->address + filesystem_data->size;
    }
    else
    {
        stage2_stack->filesystem_start = address;
        stage2_stack->filesystem_end = address;
    }

    // Construct a data object for the IGVM parameter block.
    stage2_stack->igvm_param_block = address;
    igvm_parameter_object = construct_mem_data_object(address, sizeof(IgvmParamBlock), "IGVM Parameter Block");
    igvm_parameter_block = (IgvmParamBlock *)igvm_parameter_object->data;
    memset(igvm_parameter_block, 0, sizeof(IgvmParamBlock));
    address += PAGE_SIZE;

    // Reserve a parameter page to hold IGVM parameters.
    igvm_parameter_block->param_page_offset = address - (uint32_t)igvm_parameter_object->address;
    construct_parameter_page(address, parameter_page_general, "General parameters");
    address += PAGE_SIZE;

    // Reserve a parameter page to hold the memory map.
    igvm_parameter_block->memory_map_offset = address - (uint32_t)igvm_parameter_object->address;
    construct_parameter_page(address, parameter_page_memory_map, "Memory map");
    address += PAGE_SIZE;

    // If the firmware has supplied a guest context page, then assign it an address now.
    if (fw_info.guest_context != NULL)
    {
        fw_info.guest_context->address = address;
        igvm_parameter_block->guest_context_offset = address - (uint32_t)igvm_parameter_object->address;
        address += fw_info.guest_context->size;
    }

    // Populate the rest of the parameter block.
    igvm_parameter_block->param_area_size = address - (uint32_t)igvm_parameter_object->address;
    igvm_parameter_block->cpuid_page = (uint32_t)cpuid_page->address;
    igvm_parameter_block->secrets_page = (uint32_t)secrets_page->address;
    igvm_parameter_block->debug_serial_port = com_io_ports[com_port - 1];

    if (is_hyperv)
    {
        // Place the kernel area at 64 MB with a size of 16 MB.
        igvm_parameter_block->kernel_base = 0x04000000;
        igvm_parameter_block->kernel_size = 0x01000000;

        // Add additional information if firmware is being launched.
        if (fw_info.fw_info.size != 0)
        {
            // Mark the range between the top of the stage 2 area and the base
            // of memory as a range that needs to be validated.
            fw_info.fw_info.prevalidated_count = 1;
            fw_info.fw_info.prevalidated[0].base = 0xA0000;
            fw_info.fw_info.prevalidated[0].size = fw_info.fw_info.start - 0xA0000;

            igvm_parameter_block->firmware = fw_info.fw_info;
            igvm_parameter_block->vtom = fw_info.vtom;
        }
        else
        {
            // Set the shared GPA boundary at bit 46, below the lowest possible
            // C-bit position.
            igvm_parameter_block->vtom = 0x0000400000000000;
        }

        platform->SharedGpaBoundary = igvm_parameter_block->vtom;
    }
    else
    {
        // Place the kernel area at 512 GB with a size of 16 MB.
        igvm_parameter_block->kernel_base = 0x0000008000000000;
        igvm_parameter_block->kernel_size = 0x01000000;
    }

    // Place the VMSA at the base of the kernel region and mark that page
    // as reserved.
    vmsa_address = igvm_parameter_block->kernel_base;
    igvm_parameter_block->kernel_reserved_size = 0x1000;

    // If a firmware file has been specified then add it and set the relevant 
    // parameter block entries.
    if (fw_filename && is_qemu)
    {
        igvm_parameter_block->firmware.size = fw_size;
        igvm_parameter_block->firmware.start = fw_base;
        if (!construct_file_data_object(fw_filename, fw_base))
        {
            return 1;
        }

        // If the firmware file is an OVMF binary then we can extract the OVMF
        // metadata from it. If the firmware is not OVMF then this function has
        // no effect.
        parse_ovmf_metadata(fw_filename, igvm_parameter_block);
    }

    // Generate a header to describe the memory that will be used as the
    // SVSM range.  This tells the loader that this GPA range must be populated
    // or else the image will not run.
    generate_required_memory_header(igvm_parameter_block);

    // Generate the initial VMSA.
    vmsa_data = construct_mem_data_object(vmsa_address, PAGE_SIZE, "VMSA");
    vmsa_data->data_type = IGVM_VHT_VP_CONTEXT;
    generate_initial_vmsa(vmsa_data->data);

    // Generate headers for the IGVM parameters.
    generate_parameter_headers();

    // Generate headers for all file data.
    generate_data_headers();

    // The headers are now fully constructed.  Assign file offsets to all file
    // data.
    assign_file_data();

    if (is_verbose)
    {
        print_param_block(igvm_parameter_block);
    }

    // Finally, generate the output file.
    err = generate_igvm_file(output_filename);
    if (err != 0)
    {
        return err;
    }

    return 0;
}
