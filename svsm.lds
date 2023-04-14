OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0xffffff8000000000;
	.text : {
		*(.startup.*)
		*(.text)
		*(.text.*)
		. = ALIGN(16);
		exception_table_start = .;
		KEEP(*(__exception_table))
		exception_table_end = .;
	}
	. = ALIGN(4096);
	.rodata : { *(.rodata) *(.rodata.*) }
	. = ALIGN(4096);
	.data : { *(.data) *(.data.*) }
	. = ALIGN(4096);
	.bss : {
		*(.bss) *(.bss.*)
		. = ALIGN(4096);
	}
	. = ALIGN(4096);
}

ENTRY(startup_64)
