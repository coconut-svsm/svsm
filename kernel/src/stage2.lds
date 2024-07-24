/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 64k;
	.stext = .;
	.text : {
		*(.startup.*)
		*(.text)
		*(.text.*)
		. = ALIGN(16);
		exception_table_start = .;
		KEEP(*(__exception_table))
		exception_table_end = .;
	}
	. = ALIGN(16);
	.data : { *(.data) }
	. = ALIGN(16);
	.rodata : { *(.rodata) }
	edata = .;
	. = ALIGN(4096);
	.bss : {
		_bss = .;
		*(.bss) *(.bss.[0-9a-zA-Z_]*)
		. = ALIGN(16);
		_ebss = .;
	}
	. = ALIGN(4096);
	heap_start = .;

	. = 632k;
	heap_end = .;
	SECRETS_PAGE = .;
	. = 636k;
	_reserved_for_cpuid_page = .;
}

ENTRY(startup_32)
