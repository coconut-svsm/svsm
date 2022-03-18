#include "types.h"

/* Use first 640kb of memory for stage2 loader */
#define STAGE2_RANGE_START	0
#define STAGE2_RANGE_PAGES	158

/* Stage2 is loaded at 64kb */
#define STAGE2_START		0x10000

.text
	.section ".startup.text","ax"
	.code32

	.org 0
	.globl startup_32
startup_32:
	cld
	cli

	/* Copy stage2 code to destination address */
	movl	$stage2_bin, %esi
	movl	$STAGE2_START, %edi
	movl	stage2_size, %ecx
	shrl	$2, %ecx
	rep movsl

	/* Setup stack for stage 2*/
	movl	$STAGE2_START, %esp

	/* Jump to stage 2 */
	movl	$STAGE2_START, %eax
	jmp	*%eax
	
.data

stage2_bin:
	.align	4
	.incbin "stage1/stage2.bin"
	.align	4
stage2_bin_end:
stage2_size:
	.long	stage2_bin_end - stage2_bin
