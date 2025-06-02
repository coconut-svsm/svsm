// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

.code64

.section .data
.globl HV_DOORBELL_ADDR
HV_DOORBELL_ADDR:
	.quad 0

.pushsection .entry.text, "ax"

.macro push_regs
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	pushq	%rsi
	pushq	%rdi
	pushq	%rbp
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	# rdsspq is a nop when shadow stacks are not supported. Make sure that
	# rax is 0 if that's the case.
	xorl	%eax, %eax
	rdsspq	%rax
	pushq	%rax
.endm

.macro default_entry_with_ist name: req handler:req error_code:req vector:req
	.globl asm_entry_\name
asm_entry_\name:
	asm_clac

	.if \error_code == 0
	pushq	$0
	.endif
	push_regs
	movl	$\vector, %esi
	movq	%rsp, %rdi
	xorl	%edx, %edx
	call	ex_handler_\handler
	jmp	default_return
.endm

.macro default_entry_no_ist name: req handler:req error_code:req vector:req
	.globl asm_entry_\name
asm_entry_\name:
	asm_clac

	.if \error_code == 0
	pushq	$0
	.endif
	push_regs
	testl	${IF}, {EXCEP_FLAGS_OFF}(%rsp)
	jz	L\@
	sti
L\@:
	movl	$\vector, %esi
	movq	%rsp, %rdi
	xorl	%edx, %edx
	call	ex_handler_\handler
	jmp	default_return
.endm

.macro irq_entry name:req vector:req
	.globl asm_entry_irq_\name
asm_entry_irq_\name:
	asm_clac

	pushq	$0
	push_regs
	movl	$\vector, %edi
	call	common_isr_handler_entry
	jmp	default_return
.endm

// The #HV handler is coded specially in order to deal with control flow
// alterations that may be required based on when the #HV arrives.  If the #HV
// arrives from a context in which interrupts are enabled, then the #HV can
// be handled immediately.  In general, if the #HV arrives from a context in
// which interrupts are disabled, processing is postponed to a point in time
// when interrupt processing is safe.  However, there are two cases in which
// #HV processing is required even when interrupts are disabled.
// 1. The #HV arrives just before a return to the guest VMPL.  In this case,
//    the return to the guest VMPL must be cancelled so the #HV can be handled
//    immediately.  Otherwise, if the return to the guest occurs while the #HV
//    remains pending, it will remain pending until the next time the SVSM
//    is reentered, which could block delivery of critical events while the
//    guest is executing.
// 2. The #HV arrives while preparing to execute IRET to return to a context
//    in which interrupts are enabled.  If such an #HV is not handled, then
//    it will remain pending indefinitely, which could block delivery of
//    critical events.  When an #HV arrives at a time that the IRET is
//    is committed to complete, the #HV handler will "take over" the
//    exception context established previously (the one from which the IRET
//    intends to return).  In this case, the #HV handler will complete
//    processing and will perform the IRET to the point of the original
//    exception.
.globl asm_entry_hv
asm_entry_hv:
	asm_clac

	// Push a dummy error code, and only three registers as scratch
	// registers.  If no #HV processing is required, then only these three
	// registers will need to be popped.
	pushq	$0
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	// Check whether interrupts were enabled at the time of #HV.  If so,
	// commit to processing all #HV events immediately.
	testl	${IF}, ({EXCEP_FLAGS_OFF} - {EXCEP_RCX_OFF})(%rsp)
	jnz	continue_hv
	// Fetch RIP from the trap frame.
	movq	({EXCEP_RIP_OFF} - {EXCEP_RCX_OFF})(%rsp), %rax
	// Check whether the trap RIP is within the guest VMPL return window.
	leaq	switch_vmpl_window_start(%rip), %rbx
	leaq	switch_vmpl_window_end(%rip), %rcx
	cmp	%rbx, %rax
	jb	hv_not_vmpl_switch
	cmp	%rcx, %rax
	jae	hv_not_vmpl_switch
	// RIP is in the return window, so update RIP to the cancel point.
	leaq	switch_vmpl_cancel(%rip), %rbx
	movq	%rbx, ({EXCEP_RIP_OFF} - {EXCEP_RCX_OFF})(%rsp)
	// Update RIP on the shadow stack to the cancel point.
	cmpb	$0, {IS_CET_SUPPORTED}(%rip)
	je	2f
	rdsspq	%rax
	wrssq	%rbx, 8(%rax)
2:
	// Defer any further processing until interrupts can be processed.
	jmp	postpone_hv
hv_not_vmpl_switch:
	// Load the RSP value that was live at the time of the #HV.
	movq	({EXCEP_RSP_OFF} - {EXCEP_RCX_OFF})(%rsp), %rcx
	// Check to see whether this interrupt occurred on the IRET path
	leaq	iret_return_window(%rip), %rbx
	cmp	%rbx, %rax
	jb	postpone_hv
	leaq	default_iret(%rip), %rbx
	cmp	%rbx, %rax
	ja	postpone_hv
	// RIP is within the IRET sequence, so the IRET should be aborted, and
	// the previous exception should be handled as if it were #HV.  At this
	// point, there are two possibilities.  If RIP is before the IRET
	// instruction itself, then the RSP at the time of #HV exception
	// points to the register context that was established for the previous
	// exception.  In that case, the current RSP can be changed to point
	// to that exception context, and the #HV can be handled using that
	// register context, and when #HV processing completes, the subsequent
	// end-of-interrupt flow will restore the context at the time of the
	// previous exception.  On the other hand, if RIP has advanced to the
	// point of the IRET instruction itself, then all of the registers
	// have already been reloaded with the previous exception context,
	// and the RSP at the time of #HV points at the stack frame that
	// would be consumed by the IRET instruction.  In that case, a new
	// exception context will need to be constructed.  At this point,
	// EFLAGS.ZF=1 if the previous RIP was at the IRET instruction.
	jz	restart_hv
	// Check to see whether interrupts were enabled at the time the
	// previous exception was taken.  If not, no further processing is
	// required.  This could not be performed before the RIP check because
	// the previous RIP determines where to find the previous EFLAGS.IF
	// value on the stack.
	testl	${IF}, {EXCEP_FLAGS_OFF}(%rcx)
	jz	postpone_hv
	// Switch to the stack pointer from the previous exception, which
	// points to the register save area, and continue with #HV
	// processing.
	movq	%rcx, %rsp
	// Pop the current stack frame, so that the previous stack frame sits
	// on top of the shadow stack.
	cmpb	$0, {IS_CET_SUPPORTED}(%rip)
	je	2f
	movl	$3, %eax
	incsspq	%rax
2:
	jmp	handle_as_hv

postpone_hv:
	popq	%rcx
	popq	%rbx
	popq	%rax
	// Skip error code.
	addq	$8, %rsp
	iretq

restart_hv:
	// The previous RIP was on an IRET instruction.  Before moving forward
	// with #HV processing, check to see whether interrupts were enabled at
	// the time the previous exception was taken.  If not, no further
	// processing is required.  This could not be done when RIP was
	// checked because the stack location of the previous EFLAGS.IF value
	// was not known until RIP was determined to be at the IRET
	// instruction.
	//
	// At this point, RCX holds the stack pointer at the time of the
	// IRET that was aborted.  In other words, it is pointing to
	// &X86ExceptionContext.frame.
	testl	${IF}, ({EXCEP_FLAGS_OFF} - {EXCEP_FRAME_OFF})(%rcx)
	jz	postpone_hv
	// Since interrupts were enabled in the previous exception frame,
	// #HV processing is now required.  The previous RSP points to the
	// exception frame (minus error code) as it would be consumed by
	// IRET.  In order to set up a new exception context, the three
	// registers that were saved upon entry to the #HV handler will need to
	// be copied to the top of the stack (adjacent to the space for a
	// dummy erro code).  Then, the stack pointer will be loaded with
	// the previous RSP and the remaining register state will be pushed
	// normally to create a complete exception context reflecting the
	// register state at the time of the exception that was returning at
	// the time the #HV arrived.
	//
	// The first QWORD below the RCX pointer is reserved for the dummy
	// error code, then the three QWORDS below that will hold the RAX, RBX,
	// and RCX values, which are presently stored in the top three QWORDs
	// of the current stack.  Copy them back to the previous exception
	// context and start reconstructing (or "taking over") it.
	movq	0*8(%rsp), %rax
	movq	%rax, -4*8(%rcx)
	movq	1*8(%rsp), %rax
	movq	%rax, -3*8(%rcx)
	movq	2*8(%rsp), %rax
	movq	%rax, -2*8(%rcx)
	// Load the previous stack pointer and continue reconstruction at RDX.
	leaq	-4*8(%rcx), %rsp
	// Pop the current stack frame, so that the previous stack frame sits
	// on top of the shadow stack.
	cmpb	$0, {IS_CET_SUPPORTED}(%rip)
	je	2f
	movl	$3, %eax
	incsspq	%rax
2:

continue_hv:
	// At this point, only the dummy error code and first three registers
	// have been pushed onto the stack.  Push the remainder to construct a
	// full exception context.
	pushq	%rdx
	pushq	%rsi
	pushq	%rdi
	pushq	%rbp
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	# rdsspq is a nop when shadow stacks are not supported. Make sure that
	# rdx is 0 if that's the case.
	xorl	%edx, %edx
	rdsspq	%rdx
	pushq	%rdx
handle_as_hv:
	// Load the address of the #HV doorbell page.  The global address
	// might not yet be configured, and the per-CPU page might also not
	// yet be configured, so only process events if there is a valid
	// doorbell page.
	movq	HV_DOORBELL_ADDR(%rip), %rsi
	testq	%rsi, %rsi
	jz	default_return
	movq	(%rsi), %rdi
	testq	%rdi, %rdi
	jz	default_return
handle_as_hv_with_doorbell:
	call	process_hv_events
	// fall through to default_return

.globl default_return
default_return:
	// Ensure that interrupts are disabled before attempting any return.
	cli
	testb	$3, {EXCEP_CS_OFF}(%rsp) // Check CS RPL in exception frame
	jnz	return_user
return_all_paths:
	// If interrupts were previously available, then check whether any #HV
	// events are pending.  If so, proceed as if the original trap was
	// #HV.
	testl	${IF}, {EXCEP_FLAGS_OFF}(%rsp) // check EFLAGS.IF in exception frame
	jz	begin_iret_return
	movq	HV_DOORBELL_ADDR(%rip), %rdi
	test	%rdi, %rdi
	jz	begin_iret_return
	movq	(%rdi), %rdi
	test	%rdi, %rdi
	jz	begin_iret_return
	testw	$0x8000, (%rdi)
	// The memory access to the NoFurtherSignal bit must be the last
	// instruction prior to the IRET RIP window checked by the #HV entry
	// code above.  After this point, all code must execute within this
	// instruction range to ensure that the #HV handler will be able to
	// detect any #HV that arrives after the check above, except for
	// the specific case of processing pending #HV events.
iret_return_window:
	jnz	handle_as_hv_with_doorbell
begin_iret_return:
	// Reload registers without modifying the stack pointer so that if #HV
	// occurs within this window, the saved registers are still intact.
	movq	{EXCEP_R15_OFF}(%rsp), %r15
	movq	{EXCEP_R14_OFF}(%rsp), %r14
	movq	{EXCEP_R13_OFF}(%rsp), %r13
	movq	{EXCEP_R12_OFF}(%rsp), %r12
	movq	{EXCEP_R11_OFF}(%rsp), %r11
	movq	{EXCEP_R10_OFF}(%rsp), %r10
	movq	{EXCEP_R9_OFF}(%rsp), %r9
	movq	{EXCEP_R8_OFF}(%rsp), %r8
	movq	{EXCEP_RBP_OFF}(%rsp), %rbp
	movq	{EXCEP_RDI_OFF}(%rsp), %rdi
	movq	{EXCEP_RSI_OFF}(%rsp), %rsi
	movq	{EXCEP_RDX_OFF}(%rsp), %rdx
	movq	{EXCEP_RCX_OFF}(%rsp), %rcx
	movq	{EXCEP_RBX_OFF}(%rsp), %rbx
	movq	{EXCEP_RAX_OFF}(%rsp), %rax

	// Skip error code.
	addq	${EXCEP_FRAME_OFF}, %rsp

default_iret:
	iretq

return_user:
	// Put user-mode specific return code here
	jmp	return_all_paths

.globl return_new_task
return_new_task:
	call	setup_user_task
	jmp	default_return

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
default_entry_with_ist	name=df		handler=double_fault		error_code=1	vector=8

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

// #PF Early Page-Fault Exception (Vector 14)
default_entry_no_ist	name=pf_early	handler=page_fault_early	error_code=1	vector=14

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

// #VE Virtualization Exception (Vector 20)
default_entry_no_ist	name=ve		handler=ve			error_code=0	vector=20

// #CP Control-Protection Exception (Vector 21)
default_entry_no_ist	name=cp		handler=control_protection			error_code=1	vector=21

// Vectors 22-27 not defined

// #VC VMM Communication Exception (Vector 29)
default_entry_no_ist	name=vc		handler=vmm_communication	error_code=1	vector=29

// #SX Security Exception (Vector 30)
default_entry_no_ist	name=sx		handler=panic			error_code=1	vector=30

// INT 0x80 system call handler
default_entry_no_ist	name=int80	handler=system_call		error_code=0	vector=0x80

// Interrupt injection vector
irq_entry	name=int_inj	vector=0x50

// IPI vector.
irq_entry	name=ipi	vector=0xE0

.popsection
