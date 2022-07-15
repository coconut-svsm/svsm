#[repr(C, packed)]
pub struct KernelLaunchInfo {
	pub kernel_start : u64,
	pub kernel_end   : u64,
	pub virt_base    : u64,
}
