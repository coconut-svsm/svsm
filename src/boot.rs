use core::arch::global_asm;

global_asm!(r#"
		.text
		.section ".startup.text","ax"
		.code32

		.org 0
		.globl startup_32
		startup_32:

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
		movl $pgtable_end, %ecx
		subl $pgtable, %ecx
		shrl $2, %ecx
		xorl %eax, %eax
		movl $pgtable, %edi
		rep stosl

		movl $0x8000001f, %eax
		call cpuid_ebx
		andl $0x3f, %ebx
		subl $32, %ebx
		xorl %edx, %edx
		btsl %ebx, %edx
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

		movl %cr4, %eax
		bts $5, %eax
		movl %eax, %cr4

		movl $0xc0000080, %ecx
		rdmsr
		bts $8, %eax
		wrmsr

		movl $pgtable, %eax
		movl %eax, %cr3


		movl %cr0, %eax
		bts $31, %eax
		movl %eax, %cr0

		pushl $0x18
		movl $startup_64, %eax
		pushl %eax

		lret

	cpuid_ebx:
		movl $0x9e000, %esi
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

		.code64

	startup_64:
		movw $0x20, %ax
		movw %ax, %ds
		movw %ax, %es
		movw %ax, %fs
		movw %ax, %gs
		movw %ax, %ss

		xorq %rax, %rax
		leaq _bss(%rip), %rdi
		leaq _ebss(%rip), %rcx
		subq %rdi, %rcx
		shrq $3, %rcx
		rep stosq

		jmp stage2_main

		.data

	idt32:
		.rept 32
		.quad 0
		.endr
	idt32_end:

	idt32_desc:
		.word idt32_end - idt32 - 1
		.long 0

		.align 256
	gdt64:
		.quad 0
		.quad 0x00cf9a000000ffff
		.quad 0x00cf93000000ffff
		.quad 0x00af9a000000ffff
		.quad 0x00cf92000000ffff
	gdt64_end:

	gdt64_desc:
		.word gdt64_end - gdt64 - 1
		.quad gdt64


		.align 4096
		.globl boot_ghcb
	boot_ghcb:
		.fill 4096, 1, 0

		.align 4096
		.globl pgtable
	pgtable:
		.fill 7 * 4096, 1, 0
	pgtable_end:"#, options(att_syntax));
