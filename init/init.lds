/* Temporary WA until p_vaddr alignment issue is fixed in our ELF parser */

OUTPUT_ARCH(i386:x86-64)

PHDRS
{
	text PT_LOAD FLAGS(5);		/* Read + Execute */
	rodata PT_LOAD FLAGS(4);	/* Read-only */
	data PT_LOAD FLAGS(6);		/* Read + Write */
	bss PT_LOAD FLAGS(6);		/* Read + Write */
}

SECTIONS
{
	.text : {
		*(.text)
		*(.text.*)
	} :text
	. = ALIGN(4096);
	.rodata : {
		*(.rodata)
		*(.rodata.*)
	} : rodata
	. = ALIGN(4096);
	.data : {
		*(.data)
		*(.data.*)
	} :data
	. = ALIGN(4096);
	.bss : {
		*(.bss) *(.bss.*)
		. = ALIGN(4096);
	} :bss
	. = ALIGN(4096);
}

ENTRY(init_start)
