// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

#[cfg(not(feature = "load-stage2"))]
use bootlib::igvm_params::IgvmParamBlock;
#[cfg(not(feature = "load-stage2"))]
use bootlib::kernel_launch::Stage2LaunchInfo;
#[cfg(feature = "load-stage2")]
use bootlib::kernel_launch::{CPUID_PAGE, SECRETS_PAGE, STAGE2_INFO_SZ, STAGE2_MAXLEN};
use bootlib::kernel_launch::{STAGE2_STACK, STAGE2_START};
use core::arch::global_asm;
#[cfg(not(feature = "load-stage2"))]
use core::mem::offset_of;
use core::panic::PanicInfo;

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
        /* Make sure stage 2 doesn't exceed the max allowable length */
        cmpl    ${STAGE2_MAXLEN}, %ecx
        jg      3f
        shrl    $2, %ecx
        rep movsl

        /* Setup stack for stage 2 */
        movl    ${STAGE1_STACK}, %esp

        /* Write startup information to stage 2 stack */
        xorl    %eax, %eax

        /* Reserved */
        pushl   %eax

        /* No IGVM */
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

        /* Push the end of stage 2 area as described by the metadata */
        pushl   $({STAGE2_START} + {STAGE2_MAXLEN})

        /* Push the location of the secrets page.  It is at 8 MB plus 56 KB */
        pushl   ${SECRETS_PAGE}

        /* Push the location of the CPUID page.  It is at 8 MB plus 60 KB */
        pushl   ${CPUID_PAGE}

        /* Push the value 1 to indicate SNP */
        pushl   $1

        /* Reserve space for VTOM */
        pushl   %eax
        pushl   %eax

        /* Make sure stage 2 info is completely populated */
        cmpl    ${STAGE2_STACK}, %esp
        jne     3f

        /* Clear ESI to inform stage 2 that this is the BSP */
        xorl    %esi, %esi

        jmp     .Lenter_stage2
    3:  ud2"#,
    STAGE2_START = const STAGE2_START,
    STAGE2_MAXLEN = const STAGE2_MAXLEN,
    STAGE1_STACK = const STAGE2_STACK + STAGE2_INFO_SZ,
    STAGE2_STACK = const STAGE2_STACK,
    SECRETS_PAGE = const SECRETS_PAGE,
    CPUID_PAGE = const CPUID_PAGE,
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
        movl    $({STAGE2_STACK} + {PLATFORM_TYPE_OFF}), %eax
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
        movl    $({STAGE2_STACK}), %esp
        /* %ebx is initialized with GPAW - save (1u64 << (GPAW - 1)) to vtom */
        subl    $33, %ebx
        movl    $({STAGE2_STACK} + {VTOM_OFF}), %eax
        xorl    %edx, %edx

        /* GPAW must be either 48 or 52 */
    1:  xorl    %ecx, %ecx
        movl    %ecx, (%eax)
        addl    $4, %eax
        bts     %ebx, %ecx
        movl    %ecx, (%eax)

        /* Jump if IgvmParamBlock.vtom has been fixed up */
        test    %edx, %edx
        jnz     .Lenter_stage2

        movl    $({STAGE2_STACK} + {IGVM_OFF}), %edx
        movl    (%edx), %edx
        /* %edx: &IgvmParamBlock */
        test    %edx, %edx
        jz      .Lenter_stage2

        /* Leave %edx intact to ensure we jump to .Lenter_stage2 */
        mov     %edx, %eax
        addl    ${VTOM_OFF_IGVM}, %eax
        /* %eax: &IgvmParamBlock.vtom */
        jmp     1b"#,
    STAGE2_STACK = const STAGE2_STACK,
    PLATFORM_TYPE_OFF = const offset_of!(Stage2LaunchInfo, platform_type) as u32,
    IGVM_OFF = const offset_of!(Stage2LaunchInfo, igvm_params) as u32,
    VTOM_OFF = const offset_of!(Stage2LaunchInfo, vtom) as u32,
    VTOM_OFF_IGVM = const offset_of!(IgvmParamBlock, vtom) as u32,
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
