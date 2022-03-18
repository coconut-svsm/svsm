OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = 64k;
	.stext = .;
	.text : { *(.startup.*) *(.text) *(.text.*) }
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
}

ENTRY(startup_32)
