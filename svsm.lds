OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0xffffff8000000000;
	stext = .;
	.kernel_metadata : {
		QUAD(.)
		QUAD(startup_64)
	}
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
	sdata = .;
	.data : { *(.data) }
	. = ALIGN(4096);
	edata = .;
	sdataro = .;
	. = ALIGN(4096);
	.rodata : { *(.rodata) }
	. = ALIGN(4096);
	edataro = .;
	.bss : {
		sbss = .;
		*(.bss) *(.bss.[0-9a-zA-Z_]*)
		BYTE(0) /* force linker to allocate file space */
		. = ALIGN(4096);
		ebss = .;
	}
	. = ALIGN(4096);
}

ENTRY(startup_64)
