// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

// Stage2 is loaded at 8 MB + 16 KB
const STAGE2_START: u32 = 0x808000;
const STAGE1_STACK: u32 = 0x806000;

// Reset vector
global_asm!(include_str!("reset.S"), options(att_syntax));

global_asm!(
    r#"
        .section ".startup.text","ax"
        .code32

        .org 0
        .globl startup_32
    startup_32:
        cld
        cli

        /* Enable caches */
        movl    %cr0, %eax
        andl    $~((1 << 30) | (1 << 29)), %eax
        mov     %eax, %cr0
        jmp     .Lprepare_stage2"#,
    options(att_syntax)
);

#[cfg(feature = "load-stage2")]
global_asm!(
    r#"
        .section ".startup.text","ax"
        .code32

    .Lprepare_stage2:
        /* Setup stack */
        movl    ${STAGE1_STACK}, %esp

        /* Store run-offset to %ebp */
        call    2f
    2:  popl    %ebp
        leal    2b, %eax
        subl    %eax, %ebp

        movl    $stage2_bin, %esi
        addl    %ebp, %esi
        movl    ${STAGE2_START}, %edi
        movl    $stage2_size, %ecx
        addl    %ebp, %ecx
        movl    (%ecx), %ecx
        shrl    $2, %ecx
        rep movsl

        /* Setup stack for stage 2 */
        movl    ${STAGE1_STACK}, %esp

        /* Write startup information to stage 2 stack */
        xorl    %eax, %eax
        pushl   %eax
        pushl   %eax

        movl    $kernel_fs_bin_end, %edi
        addl    %ebp, %edi
        pushl   %edi

        movl    $kernel_fs_bin, %edi
        addl    %ebp, %edi
        pushl   %edi

        movl    $kernel_elf_end, %edi
        addl    %ebp, %edi
        pushl   %edi

        movl    $kernel_elf, %edi
        addl    %ebp, %edi
        pushl   %edi

        /* The stage2 area ends at 0x8A0000. */
        pushl   $0x8A0000

        /* Push the location of the secrets page.  It is at 8 MB plus 56 KB */
        pushl   $0x806000

        /* Push the location of the CPUID page.  It is at 8 MB plus 60 KB */
        pushl   $0x807000

        /* Push the value 1 to indicate SNP */
        pushl   $1

        /* Reserve space for VTOM */
        pushl   %eax
        pushl   %eax

        /* Clear ESI to inform stage 2 that this is the BSP */
        xorl    %esi, %esi

        jmp     .Lenter_stage2"#,
    STAGE2_START = const STAGE2_START,
    STAGE1_STACK = const STAGE1_STACK,
    options(att_syntax)
);

#[cfg(not(feature = "load-stage2"))]
global_asm!(
    r#"
        .section ".startup.text","ax"
        .code32

    .Lprepare_stage2:
        /*
         * Stage 2 launch info has been prepared
         * Make sure platform type is TDP
         */
        movl    $({STAGE1_STACK} - 40), %eax
        movl    (%eax), %eax
        cmpl    $2, %eax
        je      .Lsetup_td
        ud2

    .Lsetup_td:
        /* %esi is initialized with TD CPU index */
        test    %esi, %esi
        jz      .Lsetup_bsp_stack

        /* Set up invalid stack for APs since they must run stacklessly */
        movl    $0x7ffff000, %esp
        jmp     .Lenter_stage2

    .Lsetup_bsp_stack:
        /* Set up BSP stack for stage 2 */
        movl    $({STAGE1_STACK} - 48), %esp
        /* %ebx is initialized with GPAW - save (1u64 << (GPAW - 1)) to vtom */
        mov     %esp, %eax
        /* GPAW must be either 48 or 52 */
        xorl    %ecx, %ecx
        movl    %ecx, (%eax)
        addl    $4, %eax
        subl    $33, %ebx
        bts     %ebx, %ecx
        movl    %ecx, (%eax)
        jmp     .Lenter_stage2"#,
    STAGE1_STACK = const STAGE1_STACK,
    options(att_syntax)
);

global_asm!(
    r#"
        .section ".startup.text","ax"
        .code32

    .Lenter_stage2:
        /* Jump to stage 2 */
        movl    ${STAGE2_START}, %eax
        jmp     *%eax"#,
    STAGE2_START = const STAGE2_START,
    options(att_syntax)
);

#[cfg(feature = "load-stage2")]
global_asm!(
    r#"
        .data

        .align 4
    stage2_bin:
        .incbin "bin/stage2.bin"
        .align 4
    stage2_bin_end:

    kernel_elf:
        .incbin "bin/kernel.elf"
        .align 4
    kernel_elf_end:

    kernel_fs_bin:
        .incbin "bin/svsm-fs.bin"
    kernel_fs_bin_end:

        .align 4
    stage2_size:
        .long   stage2_bin_end - stage2_bin
    "#,
    options(att_syntax)
);

// This is discarded by the linker
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
