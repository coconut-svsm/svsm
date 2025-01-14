// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use bootlib::kernel_launch::SIPI_STUB_GPA;
use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};

pub fn add_sipi_stub(compatibility_mask: u32, directives: &mut Vec<IgvmDirectiveHeader>) {
    // The SIPI stub is the code that is required on native platforms to
    // transition the processor out of real mode and into 64-bit mode when APs
    // are started.  It includes 16-bit code, 32-bit code, and 64-bit code.
    // For simplicity, to avoid having to invoke multiple build elements to
    // produce a number of separate, small code modules that are stitched
    // together, this routine (somewhat awkwardly) simply just captures the
    // required code bytes as a constant array, since this code is small and
    // will almost never change.  The assembly code and corresponding
    // disassembly are listed here for reference.
    //
    // F000: 0F 20 C0                       mov eax, cr0
    // F003: 80 C8 01                       or al, 1
    // F006: 0F 22 C0                       mov cr0, eax
    // F009: 2E 66 0F 01 16 1A 00           lgdt cs:[001A]
    // F010: EA 40 F0 08 00                 jmp 0008:F040
    // F015: CC                             int 3
    // F016: CC                             int 3
    // F017: CC                             int 3
    // F018: CC                             int 3
    // F019: CC                             int 3
    // F01A: 1F 00 20 F0 00 00
    //
    // GDT:
    // F020: 00 00 00 00 00 00 00 00 // null selector
    // F028: FF FF 00 00 00 9B CF 00 // 32-bit code
    // F030: FF FF 00 00 00 9B AF 00 // 64-bit code
    // F038: FF FF 00 00 00 93 CF 00 // data
    //
    // F040: 66 B8 18 00                    mov ax, 18h
    // F044: 8E D8                          mov ds, ax
    // F046: 8E D0                          mov ss, ax
    // F048: 8E C0                          mov es, ax
    // F04A: 8B 05 F8 FF 00 00              mov eax, [FFF8] // page table
    // F050: 0F 22 D8                       mov cr3, eax
    // F053: B9 80 00 00 C0                 mov ecx, C0000080h
    // F058: 0F 32                          rdmsr
    // F05A: 0F BA E8 08                    bts eax, 8 // EFER_LME
    // F05E: 0F 30                          wrmsr
    // F060: 0F 20 E0                       mov eax, cr4
    // F063: 83 C8 20                       or eax, 20h // CR4_PAE
    // F066: 0F 22 E0                       mov cr4, eax
    // F069: 0F 20 C0                       mov eax, cr0
    // F06C: 0F BA E8 1F                    bts eax, 1Fh
    // F070: 0F 22 C0                       mov cr0, eax // CR0_PG
    // F073: BF 00 00 01 00                 mov edi, 10000
    // F078: 2B 3D FC FF 00 00              sub edi, [FFFC] // context size
    // F07E: EA 85 F0 00 00 10 00           jmp 0010:F085
    // F085: FF 25 65 0F 00 00              jmp [FFF0] // start routine
    // F08B:

    let code_bytes: &[u8] = &[
        0x0F, 0x20, 0xC0, 0x80, 0xC8, 0x01, 0x0F, 0x22, 0xC0, 0x2E, 0x66, 0x0F, 0x01, 0x16, 0x1A,
        0x00, 0xEA, 0x40, 0xF0, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x1F, 0x00, 0x20, 0xF0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00,
        0x9B, 0xCF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x93, 0xCF, 0x00, 0x66, 0xB8, 0x18, 0x00, 0x8E, 0xD8, 0x8E, 0xD0, 0x8E, 0xC0, 0x8B,
        0x05, 0xF8, 0xFF, 0x00, 0x00, 0x0F, 0x22, 0xD8, 0xB9, 0x80, 0x00, 0x00, 0xC0, 0x0F, 0x32,
        0x0F, 0xBA, 0xE8, 0x08, 0x0F, 0x30, 0x0F, 0x20, 0xE0, 0x83, 0xC8, 0x20, 0x0F, 0x22, 0xE0,
        0x0F, 0x20, 0xC0, 0x0F, 0xBA, 0xE8, 0x1F, 0x0F, 0x22, 0xC0, 0xBF, 0x00, 0x00, 0x01, 0x00,
        0x2B, 0x3D, 0xFC, 0xFF, 0x00, 0x00, 0xEA, 0x85, 0xF0, 0x00, 0x00, 0x10, 0x00, 0xFF, 0x25,
        0x65, 0x0F, 0x00, 0x00,
    ];

    let mut page_data = Vec::<u8>::new();
    page_data.extend_from_slice(code_bytes);

    // Fill the remainder of the page with INT 3.
    page_data.resize(PAGE_SIZE_4K.try_into().unwrap(), 0xCC);

    directives.push(IgvmDirectiveHeader::PageData {
        gpa: SIPI_STUB_GPA as u64,
        compatibility_mask,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: page_data,
    });
}
