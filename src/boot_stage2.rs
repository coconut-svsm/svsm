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
        movl $6, %edi /* #UD */
        movl $ud_vmgexit_fixup_handler32, %esi
        call idt32_install_handler

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
        call get_pte_c_bit
        movl %eax, %edx

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

    get_pte_c_bit:
        /*
         * Determine the PTE C-bit position. The user could mistakenly attempt
         * to launch the SVSM in a non-SEV-SNP environment and we should handle
         * this gracefully here, so that a meaningful error can be reported at a
         * later stage when the console is functional. Ultimately, the C-bit
         * is found from CPUID 0x8000001f[%ebx]. The cpuid insn cannot be used
         * under SEV-ES or SEV-SNP, because the HV would fail to emulate it at
         * this point. Under SEV-SNP, there is the CPUID page, but that's not
         * available under either SEV or SEV-ES, where the C-bit would also
         * strictly be needed to proceed. For SEV-ES, the GHCB MSR protocol can
         * be used to retrieve the information, but not on plain SEV -- on the
         * latter, we're left only with the cpuid insn. For code simplicity, this
         * approach will also be used on SEV-SNP, the more secure CPUID page will
         * be examined at a later stage. First read from the SEV_STATUS MSR
         * to figure out whether any and which of SEV/SEV-ES/SEV-SNP is enabled.
         * The MSR might not exist if SEV is not supported at all, but this
         * will be handled gracefully by __rdmsr_safe.
         */
        movl $0xc0010131, %ecx
        call __rdmsr_safe
        testl %ecx, %ecx
        js .Lno_sev

        testl $0x01, %eax
        jz .Lno_sev

        testl $0x06, %eax
        jz .Lsev_no_es

        /*
         * First check whether the GCHB MSR exists by reading from it. If not,
         * that's inconsistent with the SEV_STATUS MSR from above, probably
         * meaning there's no SEV at all.
         */
        movl $0xc0010130, %ecx
        call __rdmsr_safe
        testl %ecx, %ecx
        js .Lno_sev

        /*
         * GHCB MSR protocol: the HV is required to put an
         * unsolicited SEV Information response into the GHCB MSR, but
         * don't rely on it for reliability reasons. Poke the HV anyway,
         * which will confirm that the HV is actually implementing the
         * GHCB MSR protocol as is mandatory for SEV-ES.
         */
        /* Save away original GHCB MSR value so that it can be restored later. */
        pushl %edx
        pushl %eax

        movl $0x002, %edi /* SEV Information Request */
        call __ghcb_msr_proto_safe
        testl %ecx, %ecx
        js .Lno_sev_restore_ghcb_msr

        /*
         * Bits 31:24 in an SEV Information Response contain the C-bit position.
         * Save away for later.
         */
        movl %eax, %ebx

        andl $0xfff, %eax
        cmpl $0x001, %eax /* SEV Information Response? */
        js .Lno_sev_restore_ghcb_msr

        /*
         * Check the announced min and max supported GHCB protocol version.
         * Versions 1 and 2 have been published as of now, so
         * min should be <= 2, max should be >= 1.
         */
        movl %edx, %eax
        andl $0xffff, %eax
        cmpl $2, %eax
        ja .Lno_sev_restore_ghcb_msr

        shrl $16, %edx
        cmpl $1, %edx
        jl .Lno_sev_restore_ghcb_msr

        /*
         * Alright, all evidence suggests that the HV is responding
         * properly to GHCB MSR protocol requests. That's convincing
         * enough that we're running under SEV-ES or SEV-SNP. As a last
         * check verify that the announced C-bit position is within
         * reasonable bounds: >= 32 and < 64.
         */
        shrl $24, %ebx
        cmpl $32, %ebx
        jl .Lno_sev_restore_ghcb_msr
        cmpl $64, %ebx
        jae .Lno_sev_restore_ghcb_msr

        /* Restore the original GHCB MSR values. */
        popl %eax
        popl %edx
        movl $0xc0010130, %ecx
        call __wrmsr_safe

        subl $32, %ebx
        xorl %eax, %eax
        btsl %ebx, %eax
        ret

    .Lno_sev_restore_ghcb_msr:
        popl %eax
        popl %edx
        movl $0xc0010130, %ecx
        call __wrmsr_safe
        jmp .Lno_sev

    .Lsev_no_es:
        /*
         * The SEV_STATUS MSR indicates SEV is enabled, but there is no
         * confirmation the MSR is actually what we think it is, i.e.
         * that we're running on SEV-capable HW. Confirm that now.
         */
        /*
         * Vendor should indicate "AuthenticAMD", maximum supported
         * extended cpuid function should cover
         * 0x8000001f ("Encrypted Memory Capabilities")
         */
        movl $0x80000000, %eax
        cpuid
        cmpl $0x68747541, %ebx
        jne .Lno_sev
        cmpl $0x444d4163, %ecx
        jne .Lno_sev
        cmpl $0x69746e65, %edx
        jne .Lno_sev
        cmpl $0x8000001f, %eax
        jl .Lno_sev

        /* 0x8000001f[%eax] shall indicate SEV support. */
        movl $0x8000001f, %eax
        cpuid
        testl $0x02, %eax
        jz .Lno_sev

        /* C-bit position is in %ebx' lowest 6 bits. */
        andl $0x3f, %ebx
        subl $32, %ebx
        xorl %eax, %eax
        btsl %ebx, %eax
        ret

    .Lno_sev:
        xorl %eax, %eax
        ret

    __ghcb_msr_proto_safe:
        movl %edi, %eax
        xorl %edx, %edx
        movl $0xc0010130, %ecx
        call __wrmsr_safe
        testl %ecx, %ecx
        jns 1f
        ret
        1: call __vmgexit_safe
        testl %eax, %eax
        jns 2f
        movl %eax, %ecx
        ret
        2: movl $0xc0010130, %ecx
        call __rdmsr_safe
        ret

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

    __vmgexit_safe:
    .Lvmgexit:
        rep vmmcall
        xorl %eax, %eax
        ret
    .Lvmgexit_fixup:
        movl $-1, %eax
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

    ud_vmgexit_fixup_handler32:
        pushl %eax
        movl 4(%esp), %eax /* saved %eip */

        cmpl $.Lvmgexit, %eax
        jne 1f
        movl $.Lvmgexit_fixup, %eax
        movl %eax, 4(%esp)

        popl %eax
        iretl

        1: int $3 /* Unexpected UD, not much we can do about it */

        .code64

    startup_64:
        /* Reload the data segments with 64bit descriptors. */
        movw $0x20, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss

        pushq   %rsi
        pushq   %rdi

        /* Prepare and load the 64bit IDT. */
        movq $6, %rdi /* #UD */
        movq $ud_vmgexit_fixup_handler64, %rsi
        call idt64_install_handler

        movq $13, %rdi /* #GP */
        movq $gp_msr_fixup_handler64, %rsi
        call idt64_install_handler

        movq $idt64_desc, %rax
        lidtq (%rax)

        /* Clear out .bss and transfer control to the main stage2 code. */
        xorq %rax, %rax
        leaq _bss(%rip), %rdi
        leaq _ebss(%rip), %rcx
        subq %rdi, %rcx
        shrq $3, %rcx
        rep stosq

        popq    %rdi
        popq    %rsi
        jmp stage2_main

    /* Export of __rdmsr_safe for use from Rust stage2. */
       .globl rdmsr_safe
    rdmsr_safe:
       movl %edi, %ecx
       call __rdmsr_safe
       movslq %ecx, %rcx
       testq %rcx, %rcx
       js 1f
       movl %eax, (%rsi)
       movl %edx, 4(%rsi)
       xorq %rax, %rax
       ret
       1: movq %rcx, %rax
       ret

    /* Export of __wrmsr_safe for use from Rust stage2. */
       .globl wrmsr_safe
    wrmsr_safe:
       movl %edi, %ecx
       movl %esi, %eax
       shrq $32, %rsi
       movl %esi, %edx
       call __wrmsr_safe
       movslq %ecx, %rax
       ret

    /* Export of __vmgexit_safe for use from Rust stage2. */
       .globl vmgexit_safe
    vmgexit_safe:
       call __vmgexit_safe
       movslq %eax, %rax
       ret

    idt64_install_handler:
       shlq $4, %rdi
       leaq idt64(%rdi), %rdi
       movw %si, (%rdi)
       movw $0x18, 2(%rdi) /* 64 bit CS */
       movw $0xef00, 4(%rdi) /* type = 0xf, dpl = 0x3, p = 1 */
       shrq $16, %rsi
       movw %si, 6(%rdi)
       shrq $16, %rsi
       movl %esi, 8(%rdi)
       ret

    gp_msr_fixup_handler64:
        pushq %rax
        movq 8+8(%rsp), %rax /* saved %rip */

        cmpq $.Lrdmsr, %rax
        jne 1f
        movq $.Lrdmsr_fixup, %rax
        movq %rax, 8+8(%rsp)
        jmp 2f

        1:cmpq $.Lwrmsr, %rax
        jne 3f
        movq $.Lwrmsr_fixup, %rax
        movq %rax, 8+8(%rsp)

        2: popq %rax
        addq $8, %rsp /* Pop off error code from the stack. */
        iretq

        3: ud2 /* Unexpected #GP, not much we can do about it. */

    ud_vmgexit_fixup_handler64:
        pushq %rax
        movq 8(%rsp), %rax /* saved %rip */

        cmpq $.Lvmgexit, %rax
        jne 1f
        movq $.Lvmgexit_fixup, %rax
        movq %rax, 8(%rsp)

        popq %rax
        iretq

        1: int $3 /* Unexpected UD, not much we can do about it */

        .data

    idt32:
        .rept 32
        .quad 0
        .endr
    idt32_end:

    idt32_desc:
        .word idt32_end - idt32 - 1
        .long idt32

    idt64:
        .rept 32
        .octa 0
        .endr
    idt64_end:

    idt64_desc:
        .word idt64_end - idt64 - 1
        .quad idt64

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
