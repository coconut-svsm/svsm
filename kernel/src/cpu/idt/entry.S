// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Authors: Joerg Roedel <jroedel@suse.de>

.code64
.section .text

.macro push_regs
        pushq   %rax
        pushq   %rbx
        pushq   %rcx
        pushq   %rdx
        pushq   %rsi
        pushq   %rdi
        pushq   %rbp
        pushq   %r8
        pushq   %r9
        pushq   %r10
        pushq   %r11
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
.endm

.macro pop_regs
        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %r11
        popq    %r10
        popq    %r9
        popq    %r8
        popq    %rbp
        popq    %rdi
        popq    %rsi
        popq    %rdx
        popq    %rcx
        popq    %rbx
        popq    %rax

        addq    $8, %rsp /* Skip error code */
.endm

.macro default_entry_no_ist name: req handler:req error_code:req vector:req
	.globl asm_entry_\name
asm_entry_\name:
	.if \error_code == 0
	pushq $0
	.endif
	push_regs
	movl	$\vector, %esi
	movq	%rsp, %rdi
	call	ex_handler_\handler
	jmp	default_return
.endm

.globl default_return
default_return:
	testb	$3, 17*8(%rsp) // Check CS in exception frame
	jnz return_user
	pop_regs
default_iret:
	iretq

return_user:
	// Put user-mode specific return code here
	pop_regs
	jmp default_iret

// #DE Divide-by-Zero-Error Exception (Vector 0)
default_entry_no_ist	name=de		handler=panic			error_code=0	vector=0

// #DB Debug Exception (Vector 1)
default_entry_no_ist	name=db		handler=debug			error_code=0	vector=1

// NMI Non-Maskable-Interrupt Exception (Vector 2)
default_entry_no_ist	name=nmi	handler=panic			error_code=0	vector=2

// #BP Breakpoint Exception (Vector 3)
default_entry_no_ist	name=bp		handler=breakpoint		error_code=0	vector=3

// #OF Overflow Exception (Vector 4)
default_entry_no_ist	name=of		handler=panic			error_code=0	vector=4

// #BR Bound-Range Exception (Vector 5)
default_entry_no_ist	name=br		handler=panic			error_code=0	vector=5

// #UD Invalid-Opcode Exception (Vector 6)
default_entry_no_ist	name=ud		handler=panic			error_code=0	vector=6

// #NM Device-Not-Available Exception (Vector 7)
default_entry_no_ist	name=nm		handler=panic			error_code=0	vector=7

// #DF Double-Fault Exception (Vector 8)
default_entry_no_ist	name=df		handler=double_fault		error_code=1	vector=8

// Coprocessor-Segment-Overrun Exception (Vector 9)
// No handler - reserved vector

// #TS Invalid-TSS Exception (Vector 10)
default_entry_no_ist	name=ts		handler=panic			error_code=1	vector=10

// #NP Segment-Not-Present Exception (Vector 11)
default_entry_no_ist	name=np		handler=panic			error_code=1	vector=11

// #SS Stack Exception (Vector 12)
default_entry_no_ist	name=ss		handler=panic			error_code=1	vector=12

// #GP General-Protection Exception (Vector 13)
default_entry_no_ist	name=gp		handler=general_protection	error_code=1	vector=13

// #PF Page-Fault Exception (Vector 14)
default_entry_no_ist	name=pf		handler=page_fault		error_code=1	vector=14

// Vector 15 not defined

// #MF x87 Floating-Point Exception-Pending (Vector 16)
default_entry_no_ist	name=mf		handler=panic			error_code=0	vector=16

// #AC Alignment-Check Exception (Vector 17)
default_entry_no_ist	name=ac		handler=panic			error_code=1	vector=17

// #MC Machine-Check Exception (Vector 18)
default_entry_no_ist	name=mce	handler=panic			error_code=0	vector=18

// #XF SIMD Floating-Point Exception (Vector 19)
default_entry_no_ist	name=xf		handler=panic			error_code=0	vector=19

// Vector 20 not defined

// #CP Control-Protection Exception (Vector 21)
default_entry_no_ist	name=cp		handler=panic			error_code=1	vector=21

// Vectors 22-27 not defined

// #HV Hypervisor Injection Exception (Vector 28)
default_entry_no_ist	name=hv		handler=hypervisor_injection	error_code=0	vector=28

// #VC VMM Communication Exception (Vector 29)
default_entry_no_ist	name=vc		handler=vmm_communication	error_code=1	vector=29

// #SX Security Exception (Vector 30)
default_entry_no_ist	name=sx		handler=panic			error_code=1	vector=30

// INT 0x80 system call handler
default_entry_no_ist	name=int80	handler=system_call		error_code=0	vector=0x80
