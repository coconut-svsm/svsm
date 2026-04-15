// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

use bootdefs::tdp_start::TdpStartContext;
use core::arch::global_asm;
use core::mem::offset_of;
use core::panic::PanicInfo;
use cpuarch::x86::CR4Flags;

global_asm!(
    r#"
        .code32

        .data
        .byte 0

        .code32
        .section .init
startup:
        movl    $0xFFFFF000, %edx

        /* Handle AP startup separately from BSP startup. */
        testl   %esi, %esi
        jnz     1f

        /* Ensure that 64-bit PTEs are enabled. */
        movl    %cr4, %eax
        orl     ${CR4_PAE}, %eax
        movl    %eax, %cr4

        /* %ebx is initialized with GPAW, so calculate the high 32 bits of
         * VTOM as (1u32 << (GPAW - 33)).  Note that ESI is known to be zero
         * because it was tested above.*/
        subl    $33, %ebx
        bts     %ebx, %esi

        /* Load the TDP platform type for boot loader use. */
        movl    $2, %eax

        /* Begin execution from the specified location */
        movl    {RSP}(%edx), %esp
        movl    {RIP}(%edx), %ecx
        jmp     *%ecx

    1:
        /* Wait until the current VP is selected for execution. */
        cmpl    %esi, {VP_INDEX}(%edx)
        pause
        jnz     1b

        /* Until the SIPI stub is consolidated with the boot loader stages,
         * retain hard-coded constants in the assembly code.  These will be
         * replaced once the SIPI stub is overhauled. */

        /* Load the GDT from the SIPI stub. */
        lgdt    [0xF01A]

        /* Perform a far jump to the SIPI entry point. */
        ljmpl   $8, $0xF040

        .section .resetvector
        jmp     startup
        "#,
    VP_INDEX = const offset_of!(TdpStartContext, vp_index),
    RIP = const offset_of!(TdpStartContext, rip),
    RSP = const offset_of!(TdpStartContext, rsp),
    CR4_PAE = const CR4Flags::PAE.bits(),
    options(att_syntax)
);

// This is discarded by the linker
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
