/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

	.code16gcc
	.section .init
/* to_pm_mode must be at 0xfffffe00 */
	.globl	to_pm_mode
to_pm_mode:
	xor	%bx, %bx
	mov	%bx, %ds
	mov	%bx, %es
	mov	%bx, %fs
	mov	%bx, %gs
	mov	%bx, %ss

	and	$~((1 << 30) | (1 << 29)), %eax
	or	$1, %al
	mov	%eax, %cr0

	lgdtl	%cs:0xfe00 + gdt32_descr - to_pm_mode
	ljmpl	$8, $protected_mode

	.code32
td_mode:
	and	$~((1 << 30) | (1 << 29)), %eax
	mov	%eax, %cr0

	lgdtl	%cs:gdt32_descr // flat 32-bit code segment
	ljmpl	$8, $protected_mode

protected_mode:
	mov	$16, %ax
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %fs
	mov	%ax, %gs
	mov	%ax, %ss
	ljmp	$0x8, $startup_32

gdt32:
	.quad	0
	.quad	0x00cf9b000000ffff // flat 32-bit code segment
	.quad	0x00cf93000000ffff // flat 32-bit data segment
gdt32_end:

gdt32_descr:
	.word	gdt32_end - gdt32 - 1
	.long	gdt32

	.globl	end_to_pm_mode
end_to_pm_mode:

	.section .sevmeta
	.incbin "bin/meta.bin"

	.code16gcc
	.section .resetvector
	mov	%cr0, %eax
	test	$1, %al
	// "JZ rel8" is compatible with both 16-bit and 32-bit mode
	jz	real_mode
	.code32
	jmp	td_mode
	.code16
real_mode:
	jmp	to_pm_mode
