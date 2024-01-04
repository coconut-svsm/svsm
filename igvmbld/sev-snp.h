// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

typedef struct {
    uint32_t EaxIn;
    uint32_t EcxIn;
    uint64_t Xcr0;
    uint64_t Xss;
    uint32_t EaxOut;
    uint32_t EbxOut;
    uint32_t EcxOut;
    uint32_t EdxOut;
    uint64_t Reserved;
} SNP_CPUID_LEAF;

typedef struct {
    uint32_t Count;
    uint32_t Reserved[3];
    SNP_CPUID_LEAF CpuidInfo[64];
} SNP_CPUID_PAGE;

typedef struct {
    uint16_t selector;
    uint16_t attributes;
    uint32_t limit;
    uint64_t base;
} SEV_SEGMENT;

typedef struct {
    SEV_SEGMENT segments[10];
    uint8_t reserved1[42];
    uint8_t vmpl;
    uint8_t cpl;
    uint32_t reserved2;
    uint64_t efer;
    uint32_t reserved3[0x1C];
    uint64_t cr4;
    uint64_t cr3;
    uint64_t cr0;
    uint64_t dr7;
    uint64_t dr6;
    uint64_t rflags;
    uint64_t rip;
    uint32_t reserved4[0x16];
    uint64_t rsp;
    uint32_t reserved5[6];
    uint64_t rax;
    uint64_t reserved6[13];
    uint64_t guest_pat;
    uint64_t reserved7[18];
    uint64_t gp_registers[16];
    uint64_t reserved8[6];
    uint64_t sev_features;
    uint64_t v_intr_ctrl;
    uint64_t exit_code;
    uint64_t vTOM;
    uint64_t tlb_id;
    uint64_t pcpu_id;
    uint64_t event_inject;
    uint64_t xcr0;
} SEV_VMSA;

enum {
    SevSegment_Es = 0,
    SevSegment_Cs,
    SevSegment_Ss,
    SevSegment_Ds,
    SevSegment_Fs,
    SevSegment_Gs,
    SevSegment_Gdt,
    SevSegment_Ldt,
    SevSegment_Idt,
    SevSegment_Tr,
};

#define SevFeature_Snp          0x0001
#define SevFeature_RestrictInj	0x0008
