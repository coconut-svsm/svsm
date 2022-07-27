/* SPDX-License-Identifier: (GPL-2.0-or-later OR MIT) */

/*
 * Copyright (c) 2022 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0x00000000;
	.stext = .;
	.text : { *(.startup.*) *(.text) *(.text.*) }
	. = ALIGN(16);
	.data : { *(.data) }
	. = ALIGN(16);
	.rodata : { *(.rodata) }
	. = ALIGN(16);
	.bss : { *(.bss) }
	. = ALIGN(16);
	edata = .;
	. = 0x000ffe00;
	.sinit = .;
	.init : {
		*(.init);
		. = 512 - 32 - 256;
		*(.sevmeta);
		. = 512 - 16;
		*(.resetvector);
		. = 512;
	}
	einit = .;
}

ENTRY(startup_32)
