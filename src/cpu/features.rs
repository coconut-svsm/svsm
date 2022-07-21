use super::cpuid::cpuid_table;

const X86_FEATURE_NX	: u32 = 20;
const X86_FEATURE_PGE	: u32 = 13;

pub fn cpu_has_nx() -> bool {
	let ret = cpuid_table(0x80000001);

	match ret {
		None => false,
		Some(c) => ((c.edx >> X86_FEATURE_NX)) & 1 == 1
	}
}

pub fn cpu_has_pge() -> bool {
	let ret = cpuid_table(0x00000001);

	match ret {
		None => false,
		Some(c) => ((c.edx >> X86_FEATURE_PGE)) & 1 == 1
	}
}
