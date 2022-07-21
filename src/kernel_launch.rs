pub struct KernelLaunchInfo {
	pub kernel_start : u64,
	pub kernel_end   : u64,
	pub virt_base    : u64,
	pub cpuid_page	 : u64,
	pub secrets_page : u64,
	pub ghcb         : u64,
}
