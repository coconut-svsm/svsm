/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.text ALIGN(.sdata - SIZEOF(.text) - 4095, 4096) : {
		.stext = .;
		*(.startup.*)
		*(.text.*)
	}

	/*
	 * Subtract an extra byte so that edata and the .init function
	 * symbols don't alias, which would be confusing when
	 * examining the resulting binary.
	 */
	.data ALIGN(.sinit - SIZEOF(.data) - 4095 - 1, 4096) : {
		.sdata = .;
		*(.data)
		edata = .;
	}

	.init 0xfffffe00 : {
		.sinit = .;
		*(.init);
	}
	.reset 0xfffffff0 : {
		*(.resetvector);
		. = 0x100000000;
		einit = .;
	}

	/DISCARD/ : {
		*(.eh_frame*)
	}
}

ENTRY(startup_32)
