OUTPUT_ARCH(i386:x86-64)

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC FLAGS(0);
}

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
	} :text
	. = ALIGN(4096);
	.rodata : { *(.rodata) *(.rodata.*) } :rodata
	.dynamic : { *(.dynamic) } :dynamic :rodata
	. = ALIGN(4096);
	.data : { *(.data) *(.data.*) } :data
	. = ALIGN(4096);
	edata = .;
	.bss : {
		*(.bss) *(.bss.*)
		. = ALIGN(4096);
	} :data
	. = ALIGN(4096);
}

ENTRY(startup_64)
