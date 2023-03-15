OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0xffffff8000000000;
	stext = .;
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
	etext = .;
	sdataro = .;
	.rodata : { *(.rodata) }
	. = ALIGN(4096);
	edataro = .;
	sdata = .;
	.data : { *(.data) }
	. = ALIGN(4096);
	edata = .;
	.bss : {
		sbss = .;
		*(.bss) *(.bss.[0-9a-zA-Z_]*)
		. = ALIGN(4096);
		ebss = .;
	}
	. = ALIGN(4096);
}

ENTRY(startup_64)
