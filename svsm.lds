OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 0xffffff8000000000;
	stext = .;
	.kernel_metadata : {
		QUAD(.)
		QUAD(startup_64)
	}
	.text : { *(.startup.*) *(.text) *(.text.*) }
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
		. = ALIGN(4096);
		ebss = .;
	}
	. = ALIGN(4096);
	heap_start = .;
}

ENTRY(startup_64)
