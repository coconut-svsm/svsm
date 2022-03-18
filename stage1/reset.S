#define	ENTRY(name)	\
	.globl	name;	\
	name:
#define END(name)	ENTRY(end_##name)

	.code16gcc
	.section .init
ENTRY(to_pm_mode)
	xor	%ax, %ax
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %fs
	mov	%ax, %gs
	mov	%ax, %ss

	mov	%cr0, %eax
	and	$~((1 << 30) | (1 << 29)), %eax
	or	$1, %al
	mov	%eax, %cr0

	lgdtl	%cs:0xfe00 + gdt32_descr - to_pm_mode
	ljmpl	$8, $0xfffffe00 + protected_mode - to_pm_mode

	.code32
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
	.long	0xfffffe00 + gdt32 - to_pm_mode

END(to_pm_mode)

	.section .sevmeta
	.incbin "stage1/meta.bin"

	.code16gcc
	.section .resetvector
	jmp	to_pm_mode
