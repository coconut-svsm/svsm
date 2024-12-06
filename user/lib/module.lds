/* SPDX-License-Identifier: MIT */

/*
 * Copyright (c) 2024 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

PHDRS
{
    text PT_LOAD FLAGS(0x5); /* Read + Execute */
    rodata PT_LOAD FLAGS(4);   /* Read-only */
    data PT_LOAD FLAGS(0x6); /* Read + Write */
    bss PT_LOAD FLAGS(0x6);  /* Read + Write */
}

SECTIONS
{
	. = 64k;
	_stext = .;
	.text : {
		*(.text)
		*(.text.*)
		. = ALIGN(16);
	} :text
	_etext = .;
	. = ALIGN(4096);
	.got : {
		*(.got)
		*(.got.*)
	} :data
	. = ALIGN(4096);
	_sdata = .;
	.data : {
		*(.data)
		*(.data.*)
		. = ALIGN(16);
	} :data
	_edata = .;
	. = ALIGN(4096);
	_srodata = .;
	.rodata : {
		*(.rodata)
		*(.rodata.*)
		. = ALIGN(16);
	} :rodata
	_erodata = .;
	. = ALIGN(4096);
	.bss : {
		_bss = .;
		*(.bss) *(.bss.[0-9a-zA-Z_]*)
		. = ALIGN(16);
		_ebss = .;
	} :bss
	. = ALIGN(4096);
	heap_start = .;
}

ENTRY(_start)
