use crate::types::{VirtAddr, SVSM_CS, SVSM_DS};
use core::arch::asm;

#[repr(packed)]
pub struct GdtDesc {
	size : u16,
	addr : VirtAddr,
}

const GDT_SIZE : u16 = 6;

static GDT : [ u64; GDT_SIZE as usize] = [
	0,
	0x00af9a000000ffff, // 64-bit code segment
	0x00cf92000000ffff, // 64-bit data segment
	0,
	0,
	0
];

static mut GDT_DESC : GdtDesc = GdtDesc {
	size : 0,
	addr : 0,
};

pub fn load_gdt() {
	let vaddr = GDT.as_ptr() as VirtAddr;

	unsafe {
		GDT_DESC.addr = vaddr;
		GDT_DESC.size = (GDT_SIZE * 8) - 1;

		asm!(r#" /* Load GDT */
			 lgdt	(%rax)

			 /* Reload data segments */
			 movw	%cx, %ds
			 movw	%cx, %es
			 movw	%cx, %fs
			 movw	%cx, %gs
			 movw	%cx, %ss

			 /* Reload code segment */
			 pushq	%rdx
			 leaq	1f(%rip), %rax
			 pushq	%rax
			 lretq
		1:
			 "#,
			in("rax") &GDT_DESC,
			in("rdx") SVSM_CS,
			in("rcx") SVSM_DS,
			options(att_syntax)); 
	}
}
