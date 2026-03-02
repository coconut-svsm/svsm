/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.sdata = ALIGN(.sinit - SIZEOF(.data) - 4095, 4096);
	. = .sdata;
	.data : { *(.data) }
	edata = .;

	. = 0xfffffe00;
	.sinit = .;
	.init : {
		*(.init);
		. = 512 - 16;
		*(.resetvector);
		. = 512;
	}
	einit = .;

	/DISCARD/ : {*(.*)}
}
