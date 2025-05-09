/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	/* Base address is 8 MB + 32 KB */
	. = 8m + 32k;
	.stext = .;
	.text : {
		*(.startup.*)
		*(.text)
		*(.text.*)
		. = ALIGN(16);
		early_exception_table_start = .;
		KEEP(*(__early_exception_table))
		early_exception_table_end = .;
		. = ALIGN(16);
		exception_table_start = .;
		KEEP(*(__exception_table))
		exception_table_end = .;
	}
	. = ALIGN(16);
	.data : { *(.data) }
	edata = .;
	. = ALIGN(16);
	.bss : {
		_bss = .;
		*(.bss) *(.bss.[0-9a-zA-Z_]*)
		. = ALIGN(16);
		_ebss = .;
	}
	/* Move rodata to follow bss so that the in-memory image has the same
	 * length as the ELF image.  This is required so that the IGVM
	 * builder does not have to parse the ELF file to know how much space
	 * to reserve for BSS. */
	. = ALIGN(16);
	.rodata : { *(.rodata) }
}

ENTRY(startup_32)
