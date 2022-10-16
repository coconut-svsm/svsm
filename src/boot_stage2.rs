// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use core::arch::global_asm;

global_asm!(r#"
        .text
        .section ".startup.text","ax"
        .code32

        .org 0
        .globl startup_32
        startup_32:

        /*
         * Load a GDT. Despite the naming, it contains valid
         * entries for both, "legacy" 32bit and long mode each.
         */
        movl $gdt64_desc, %eax
        lgdt (%eax)

        movw $0x10, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss

        pushl $0x8
        movl $.Lon_svsm32_cs, %eax
        pushl %eax
        lret

    .Lon_svsm32_cs:
        push    %esi
        push    %edi

        /* Prepare and load the 32bit IDT. */
        movl $13, %edi /* #GP */
        movl $gp_msr_fixup_handler32, %esi
        call idt32_install_handler

        movl $idt32_desc, %eax
        lidtl (%eax)

        /* Clear out the static page table pages. */
        movl $pgtable_end, %ecx
        subl $pgtable, %ecx
        shrl $2, %ecx
        xorl %eax, %eax
        movl $pgtable, %edi
        rep stosl

        /* Determine the C-bit position within PTEs. */
        movl $0x8000001f, %eax
        call cpuid_ebx
        andl $0x3f, %ebx
        subl $32, %ebx
        xorl %edx, %edx
        btsl %ebx, %edx

        /* Populate the static page table pages with an identity mapping. */
        movl $pgtable, %edi
        leal 0x1007(%edi), %eax
        movl %eax, 0(%edi)
        addl %edx, 4(%edi)

        addl $0x1000, %edi
        leal 0x1007(%edi), %eax
        movl $4, %ecx
        1: movl %eax, 0(%edi)
        addl %edx, 4(%edi)
        addl $0x1000, %eax
        addl $8, %edi
        decl %ecx
        jnz 1b
        andl $0xfffff000, %edi

        addl $0x1000, %edi
        movl $0x00000183, %eax
        movl $2048, %ecx
        1: movl %eax, 0(%edi)
        addl %edx, 4(%edi)
        addl $0x00200000, %eax
        addl $8, %edi
        decl %ecx
        jnz 1b

        /* Enable 64bit PTEs, CR4.PAE. */
        movl %cr4, %eax
        bts $5, %eax
        movl %eax, %cr4

        /* Enable long mode, EFER.LME. */
        movl $0xc0000080, %ecx
        rdmsr
        bts $8, %eax
        wrmsr

        /* Load the static page table root. */
        movl $pgtable, %eax
        movl %eax, %cr3

        /* Enable paging, CR0.PG. */
        movl %cr0, %eax
        bts $31, %eax
        movl %eax, %cr0

        popl    %edi
        popl    %esi

        pushl $0x18
        movl $startup_64, %eax
        pushl %eax

        lret

    cpuid_ebx:
        movl $0x9f000, %esi
        mov (%esi), %ecx
        addl $0x10, %esi
        xorl %ebx, %ebx
        1: cmpl %eax, (%esi)
        jne 2f
        movl 28(%esi), %ebx
        jmp 3f
        2: addl $0x30, %esi
        decl %ecx
        jmp 1b
        3: ret

    __rdmsr_safe:
    .Lrdmsr:
        rdmsr
        xorl %ecx, %ecx
        ret
    .Lrdmsr_fixup:
        movl $-1, %ecx
        ret

    __wrmsr_safe:
    .Lwrmsr:
        wrmsr
        xorl %ecx, %ecx
        ret
    .Lwrmsr_fixup:
        movl $-1, %ecx
        ret

    idt32_install_handler:
       leal idt32(, %edi, 8), %edi
       movw %si, (%edi)
       movw $8, 2(%edi) /* 32 bit CS */
       movw $0xef00, 4(%edi) /* type = 0xf, dpl = 0x3, p = 1 */
       shrl $16, %esi
       movw %si, 6(%edi)
       ret

    gp_msr_fixup_handler32:
        pushl %eax
        movl 4+4(%esp), %eax /* saved %eip */

        cmpl $.Lrdmsr, %eax
        jne 1f
        movl $.Lrdmsr_fixup, %eax
        movl %eax, 4+4(%esp)
        jmp 2f

        1:cmpl $.Lwrmsr, %eax
        jne 3f
        movl $.Lwrmsr_fixup, %eax
        movl %eax, 4+4(%esp)

        2: popl %eax
        addl $4, %esp /* Pop off error code from the stack. */
        iretl

        3: ud2 /* Unexpected #GP, not much we can do about it. */

        .code64

    startup_64:
        /* Reload the data segments with 64bit descriptors. */
        movw $0x20, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss

        /* Clear out .bss and transfer control to the main stage2 code. */
        pushq   %rdi
        xorq %rax, %rax
        leaq _bss(%rip), %rdi
        leaq _ebss(%rip), %rcx
        subq %rdi, %rcx
        shrq $3, %rcx
        rep stosq
        popq    %rdi

        jmp stage2_main

        .data

    idt32:
        .rept 32
        .quad 0
        .endr
    idt32_end:

    idt32_desc:
        .word idt32_end - idt32 - 1
        .long idt32

        .align 256
    gdt64:
        .quad 0
        .quad 0x00cf9a000000ffff /* 32 bit code segment */
        .quad 0x00cf93000000ffff /* 32 bit data segment */
        .quad 0x00af9a000000ffff /* 64 bit code segment */
        .quad 0x00cf92000000ffff /* 64 bit data segment */
    gdt64_end:

    gdt64_desc:
        .word gdt64_end - gdt64 - 1
        .quad gdt64

        .align 4096
        .globl pgtable
    pgtable:
        .fill 7 * 4096, 1, 0
    pgtable_end:"#, options(att_syntax));
