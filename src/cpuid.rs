use crate::{println};

const SNP_CPUID_MAX_COUNT : usize = 64;

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct SnpCpuidFn {
	eax_in     : u32,
	ecx_in     : u32,
	xcr0_in    : u64,
	xss_in     : u64,
	eax_out    : u32,
	ebx_out    : u32,
	ecx_out    : u32,
	edx_out    : u32,
	reserved_1 : u64,
}

#[repr(C, packed)]
pub struct SnpCpuidTable {
	count      : u32,
	reserved_1 : u32,
	reserved_2 : u64,
	func	   : [SnpCpuidFn; SNP_CPUID_MAX_COUNT],
}

pub fn dump_cpuid_table() {
	unsafe {
		let cpuid : *const SnpCpuidTable = 0x9e000 as *const SnpCpuidTable;
		let count = (*cpuid).count as usize;

		println!("CPUID Table entry count: {}", count);

		for i in 0..count {
			let eax_in = (*cpuid).func[i].eax_in;
			let ecx_in = (*cpuid).func[i].ecx_in;
			let xcr0_in = (*cpuid).func[i].xcr0_in;
			let xss_in = (*cpuid).func[i].xss_in;
			let eax_out = (*cpuid).func[i].eax_out;
			let ebx_out = (*cpuid).func[i].ebx_out;
			let ecx_out = (*cpuid).func[i].ecx_out;
			let edx_out = (*cpuid).func[i].edx_out;
			println!("EAX_IN: {:#010x} ECX_IN: {:#010x} XCR0_IN: {:#010x} XSS_IN: {:#010x} EAX_OUT: {:#010x} EBX_OUT: {:#010x} ECX_OUT: {:#010x} EDX_OUT: {:#010x}",
					eax_in, ecx_in, xcr0_in, xss_in, eax_out, ebx_out, ecx_out, edx_out);
		}
	}
}
