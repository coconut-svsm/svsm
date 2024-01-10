// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

#include "igvmbld.h"

typedef struct {
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t efer;
    uint64_t gdt_base;
    uint32_t gdt_limit;
    uint16_t code_selector;
    uint16_t data_selector;
    uint64_t rip;
    uint64_t gp_registers[16];
} IgvmGuestContext;

int get_next_var_hdr(
    uint8_t *var_hdrs,
    uint32_t *var_hdr_offset,
    uint32_t var_hdr_size,
    IGVM_VHS *found_header)
{
    uint32_t header_size;
    IGVM_VAR_HEADER *var_hdr;

    // Make sure the variable header data is large enough to accommodate this
    // variable header.
    var_hdr = (IGVM_VAR_HEADER *)(var_hdrs + *var_hdr_offset);
    if (*var_hdr_offset + sizeof(IGVM_VAR_HEADER) > var_hdr_size)
    {
        return 0;
    }

    header_size = sizeof(IGVM_VAR_HEADER) + var_hdr->header_size;
    header_size = (header_size + 7) & ~7;
    if (*var_hdr_offset + header_size > var_hdr_size)
    {
        return 0;
    }

    found_header->header_type = var_hdr->header_type;
    found_header->header_size = var_hdr->header_size;
    found_header->data = var_hdr + 1;

    *var_hdr_offset += header_size;

    return 1;
}

void fill_guest_context(IgvmGuestContext *guest_context, SEV_VMSA *vmsa)
{
    int i;

    guest_context->cr0 = vmsa->cr0;
    guest_context->cr3 = vmsa->cr3;
    guest_context->cr4 = vmsa->cr4;
    guest_context->efer = vmsa->efer;
    guest_context->gdt_base = vmsa->segments[SevSegment_Gdt].base;
    guest_context->gdt_limit = vmsa->segments[SevSegment_Gdt].limit;
    guest_context->code_selector = vmsa->segments[SevSegment_Cs].selector;
    guest_context->data_selector = vmsa->segments[SevSegment_Ds].selector;
    guest_context->rip = vmsa->rip;
    for (i = 0; i < 16; ++i)
    {
        guest_context->gp_registers[i] = vmsa->gp_registers[i];
    }
}

int read_hyperv_igvm_file(const char *file_name, FirmwareIgvmInfo *fw_info)
{
    uint32_t compatibility_mask;
    DATA_OBJ *data_obj;
    FILE *file;
    IGVM_FIXED_HEADER fixed_header;
    IgvmGuestContext *guest_context;
    IGVM_VHS *header;
    uint64_t highest_gpa;
    uint64_t lowest_gpa;
    IGVM_VHS_PAGE_DATA page_data;
    IGVM_VHS_PARAMETER *parameter;
    IGVM_VHS_PARAMETER_AREA *parameter_area;
    IGVM_VHS_PARAMETER_INSERT parameter_insert;
    IGVM_VHS_SUPPORTED_PLATFORM platform_header;
    uint64_t start_rip;
    IGVM_VHS var_hdr;
    uint32_t var_hdr_offset;
    void *var_hdrs;
    SEV_VMSA *vmsa;
    IGVM_VHS_VP_CONTEXT vp_context;

    file = fopen(file_name, "r");
    if (file == NULL)
    {
        fprintf(stderr, "could not open %s\n", file_name);
        return 1;
    }

    var_hdrs = NULL;

    // Read the fixed header to determine where the variable headers are.
    if (fread(&fixed_header, sizeof(IGVM_FIXED_HEADER), 1, file) != 1)
    {
ReadError:
        fprintf(stderr, "failed to read %s\n", file_name);
        fclose(file);
        if (var_hdrs != NULL)
        {
            free(var_hdrs);
        }
        return 1;
    }

    if ((fixed_header.Magic != IGVM_MAGIC) ||
        (fixed_header.FormatVersion > 2) ||
        (fixed_header.VariableHeaderOffset < sizeof(IGVM_FIXED_HEADER)))
    {
        goto ReadError;
    }

    // Support a maximum of 1 MB of variable headers in this implementation.
    if (fixed_header.VariableHeaderSize >= (1 << 20))
    {
        goto ReadError;
    }

    // Make a local copy of the variable header data.
    var_hdrs = malloc(fixed_header.VariableHeaderSize);
    if (0 != fseek(file, fixed_header.VariableHeaderOffset, SEEK_SET))
    {
        goto ReadError;
    }
    if (fread(var_hdrs, 1, fixed_header.VariableHeaderSize, file) != fixed_header.VariableHeaderSize)
    {
        goto ReadError;
    }

    // Scan the variable headers looking for an SNP platform header.
    var_hdr_offset = 0;
    compatibility_mask = 0;
    while (var_hdr_offset < fixed_header.VariableHeaderSize)
    {
        if (!get_next_var_hdr(
            var_hdrs,
            &var_hdr_offset,
            fixed_header.VariableHeaderSize,
            &var_hdr))
        {
IncompatibleFile:
            fprintf(stderr, "%s is not a compatible IGVM file\n", file_name);
            fclose(file);
            free(var_hdrs);
            return 1;
        }

        if (var_hdr.header_type == IGVM_VHT_SUPPORTED_PLATFORM)
        {
            if (var_hdr.header_size < sizeof(IGVM_VHS_SUPPORTED_PLATFORM))
            {
                goto IncompatibleFile;
            }

            memcpy(&platform_header, var_hdr.data, sizeof(IGVM_VHS_SUPPORTED_PLATFORM));
            if ((platform_header.PlatformType == IgvmPlatformType_SevSnp) &&
                (platform_header.PlatformVersion == 1))
            {
                if (platform_header.HighestVtl != 0)
                {
                    goto IncompatibleFile;
                }

                compatibility_mask = platform_header.CompatibilityMask;
                break;
            }
        }
    }

    if ((compatibility_mask == 0) ||
        ((compatibility_mask & (compatibility_mask - 1)) != 0))
    {
        goto IncompatibleFile;
    }

    // Now process all variable headers again to process the data.
    highest_gpa = 0;
    lowest_gpa = highest_gpa - 1;
    guest_context = NULL;

    var_hdr_offset = 0;
    while (var_hdr_offset < fixed_header.VariableHeaderSize)
    {
        if (!get_next_var_hdr(
            var_hdrs,
            &var_hdr_offset,
            fixed_header.VariableHeaderSize,
            &var_hdr))
        {
            goto IncompatibleFile;
        }

        switch (var_hdr.header_type)
        {
        case IGVM_VHT_SUPPORTED_PLATFORM:
            // The platform header was processed earlier.
            break;

        case IGVM_VHT_PARAMETER_AREA:
            if (var_hdr.header_size != sizeof(IGVM_VHS_PARAMETER_AREA))
            {
                goto IncompatibleFile;
            }

            // Generate a new parameter area, offset by the number of
            // parameter pages used by the SVSM.
            header = allocate_var_headers(
                IGVM_VHT_PARAMETER_AREA,
                sizeof(IGVM_VHS_PARAMETER_AREA),
                sizeof(IGVM_VHS_PARAMETER_AREA),
                1);
            parameter_area = header->data;
            memcpy(parameter_area, var_hdr.data, sizeof(IGVM_VHS_PARAMETER_AREA));

            if (parameter_area->FileOffset != 0)
            {
                goto IncompatibleFile;
            }

            parameter_area->ParameterPageIndex += num_parameter_pages;
            break;

        case IGVM_VHT_PARAMETER_INSERT:
            if (var_hdr.header_size != sizeof(IGVM_VHS_PARAMETER_INSERT))
            {
                goto IncompatibleFile;
            }

            // Generate an insertion directive with the correctly modified
            // parameter area index, but only if the directive matches the
            // compatibility mask.
            memcpy(&parameter_insert, var_hdr.data, sizeof(IGVM_VHS_PARAMETER_INSERT));
            if (parameter_insert.CompatibilityMask & compatibility_mask)
            {
                parameter_insert.ParameterPageIndex += num_parameter_pages;
                if (parameter_insert.GPA >= highest_gpa)
                {
                    highest_gpa = parameter_insert.GPA + PAGE_SIZE;
                }
                if (parameter_insert.GPA < lowest_gpa)
                {
                    lowest_gpa = parameter_insert.GPA;
                }
                header = allocate_var_headers(
                    IGVM_VHT_PARAMETER_INSERT,
                    sizeof(IGVM_VHS_PARAMETER_INSERT),
                    sizeof(IGVM_VHS_PARAMETER_INSERT),
                    1);
                memcpy(header->data, &parameter_insert, sizeof(IGVM_VHS_PARAMETER_INSERT));
            }

            break;

        case IGVM_VHT_VP_COUNT_PARMETER:
        case IGVM_VHT_MEMORY_MAP:
        case IGVM_VHT_ENVIRONMENT_INFO_PARAMETER:
        case IGVM_VHT_COMMAND_LINE:
        case IGVM_VHT_MADT:
        case IGVM_VHT_SRAT:
            if (var_hdr.header_size != sizeof(IGVM_VHS_PARAMETER))
            {
                goto IncompatibleFile;
            }

            // Generate a directive with the correctly modified parameter area
            // index.
            header = allocate_var_headers(
                    var_hdr.header_type,
                    sizeof(IGVM_VHS_PARAMETER),
                    sizeof(IGVM_VHS_PARAMETER),
                    1);
            parameter = header->data;
            memcpy(parameter, var_hdr.data, sizeof(IGVM_VHS_PARAMETER));
            parameter->ParameterPageIndex += num_parameter_pages;
            break;

        case IGVM_VHT_PAGE_DATA:
            if (var_hdr.header_size != sizeof(IGVM_VHS_PAGE_DATA))
            {
                goto IncompatibleFile;
            }

            // Determine whether this page data is selected for the correct
            // platform.  If so, the behavior depends on the type of page
            // data.
            memcpy(&page_data, var_hdr.data, sizeof(IGVM_VHS_PAGE_DATA));
            if (page_data.CompatibilityMask & compatibility_mask)
            {
                if ((page_data.Flags & ~2) != 0)
                {
                    goto IncompatibleFile;
                }

                // The page at zero is special: it includes logic to PVALIDATE
                // the first 1 MB of memory.  That should be skipped when
                // running under an SVSM because that memory is validated by
                // the SVSM itself.  In this case, the page is read to extract
                // the true starting RIP, but the page data itself is not
                // inserted into the final IGVM file.
                if (page_data.GPA == 0)
                {
                    if (page_data.FileOffset == 0)
                    {
                        goto IncompatibleFile;
                    }
                    if (0 != fseek(file, page_data.FileOffset, SEEK_SET))
                    {
                        goto ReadError;
                    }
                    if (fread(&start_rip, sizeof(uint64_t), 1, file) != 1)
                    {
                        goto ReadError;
                    }
                    continue;
                }

                if (page_data.GPA >= highest_gpa)
                {
                    highest_gpa = page_data.GPA + PAGE_SIZE;
                }
                if (page_data.GPA < lowest_gpa)
                {
                    lowest_gpa = page_data.GPA;
                }

                switch (page_data.DataType)
                {
                case IgvmPageType_Normal:
                case IgvmPageType_Cpuid:
                case IgvmPageType_CpuidExtendedFeatures:
                    // CPUID pages can be manifested directly in the firmware
                    // address space; they do not have to be pre-processed by
                    // the SVSM.
                    if (page_data.FileOffset == 0)
                    {
                        data_obj = construct_empty_data_object(page_data.GPA, PAGE_SIZE, file_name);
                        data_obj->page_type = page_data.DataType;
                    }
                    else
                    {
                        if (page_data.FileOffset + PAGE_SIZE > fixed_header.TotalFileSize)
                        {
                            goto ReadError;
                        }
                        data_obj = construct_mem_data_object(page_data.GPA, PAGE_SIZE, file_name);
                        data_obj->page_type = page_data.DataType;

                        if (0 != fseek(file, page_data.FileOffset, SEEK_SET))
                        {
                            goto ReadError;
                        }
                        if (fread(data_obj->data, 1, PAGE_SIZE, file) != PAGE_SIZE)
                        {
                            goto ReadError;
                        }
                    }

                    data_obj->page_data_flags = page_data.Flags;

                    break;

                case IgvmPageType_Secrets:
                    // The secrets page is not manifested in the final file.
                    // Instead, simply capture the location of the secrets
                    // page so it can be copied into the correct location by
                    // the SVSM.
                    fw_info->fw_info.secrets_page = (uint32_t)page_data.GPA;
                    if (fw_info->fw_info.secrets_page != page_data.GPA)
                    {
                        goto IncompatibleFile;
                    }

                    // The Hyper-V firmware reserves the page following the
                    // secrets page for the calling area.
                    fw_info->fw_info.caa_page = fw_info->fw_info.secrets_page + PAGE_SIZE;

                    break;
                }
            }

            break;

        case IGVM_VHT_VP_CONTEXT:
            if (var_hdr.header_size < FIELD_OFFSET(IGVM_VHS_VP_CONTEXT, padding))
            {
                goto IncompatibleFile;
            }

            // Determine whether this VP context is selected for the correct
            // platform.  If so, the VP context will be extracted into a
            // structure that will be included in the IGVM parameter block of
            // the new IGVM file.
            memcpy(&vp_context, var_hdr.data, sizeof(IGVM_VHS_VP_CONTEXT));
            if (vp_context.CompatibilityMask & compatibility_mask) {
                if (vp_context.VpIndex != 0)
                {
                    goto IncompatibleFile;
                }

                vmsa = malloc(sizeof(SEV_VMSA));
                if (0 != fseek(file, vp_context.FileOffset, SEEK_SET))
                {
                    free(vmsa);
                    goto ReadError;
                }
                if (fread(vmsa, sizeof(SEV_VMSA), 1, file) != 1)
                {
                    free(vmsa);
                    goto ReadError;
                }

                // Construct this data object without an address; its address
                // will be populated later.  Note that the address specified
                // in the VP context object here is not relevant, because the
                // SVSM IGVM headers expect the guest context to be part of
                // the IGVM parameter area.
                data_obj = construct_mem_data_object(0, PAGE_SIZE, file_name);
                guest_context = data_obj->data;
                memset(guest_context, 0, PAGE_SIZE);
                fill_guest_context(guest_context, vmsa);

                if (vmsa->sev_features & SevFeature_VTOM)
                {
                    fw_info->vtom = vmsa->vTOM;
                }

                free(vmsa);
                fw_info->guest_context = data_obj;
            }

            break;

        case IGVM_VHT_REQUIRED_MEMORY:
        case IGVM_VHT_SNP_POLICY:
            // This can be ignored when importing firmware files.
            break;

        default:
            goto IncompatibleFile;
        }
    }

    // The base of the firmware must be above 640K.
    if (lowest_gpa < 0xA0000)
    {
        goto IncompatibleFile;
    }

    fw_info->fw_info.start = (uint32_t)lowest_gpa;
    fw_info->fw_info.size = (uint32_t)(highest_gpa - lowest_gpa);
    fw_info->fw_info.in_low_memory = 1;

    if ((fw_info->fw_info.start != lowest_gpa) ||
        (fw_info->fw_info.start + fw_info->fw_info.size) != highest_gpa)
    {
        goto IncompatibleFile;
    }

    // If the starting RIP was fetched from GPA zero, then place it into the
    // initial context now.
    if ((start_rip != 0) && (guest_context != NULL))
    {
        if (start_rip != (uint32_t)start_rip)
        {
            goto IncompatibleFile;
        }
        guest_context->rip = start_rip;
    }

    fclose(file);
    free(var_hdrs);

    return 0;
}
