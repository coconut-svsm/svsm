#![no_std]
#![no_main]
#![feature(const_mut_refs)]

pub mod kernel_launch;

use kernel_launch::KernelLaunchInfo;
use core::panic::PanicInfo;
use core::arch::global_asm;

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %rdx will contain the offset from the phys->virt offset
 * %r8  will contain a pointer to the KernelLaunchInfo structure
 */
global_asm!(r#"
		.text
		.section ".startup.text","ax"
		.code64
		.quad	0xffffff8000000000
		.quad	startup_64
		
		.org	0x80

		.globl	startup_64
	startup_64:
		/* Save PHYS_OFFSET */
		movq	%rdx, PHYS_OFFSET(%rip)

		/* Setup stack */
		leaq bsp_stack_end(%rip), %rsp

		/* Jump to rust code */
		movq	%r8, %rdi
		jmp	svsm_main
		
		.data

		.globl PHYS_OFFSET
	PHYS_OFFSET:
		.quad 0

		.align 4096
	bsp_stack:
		.fill 4096, 1, 0
	bsp_stack_end:
	
		"#, options(att_syntax));

extern "C" {
	pub static PHYS_OFFSET : u64;
}

#[no_mangle]
pub extern "C" fn svsm_main(_launch_info : &KernelLaunchInfo) {
	panic!("Road ends here!");
}

#[panic_handler]
fn panic(_info : &PanicInfo) -> ! {
	loop { }
}
