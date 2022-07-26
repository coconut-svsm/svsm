use crate::cpu::msr::{read_msr, write_msr, SEV_STATUS, SEV_GHCB};
use crate::mm::pagetable::{flush_tlb_global};
use super::types::{PhysAddr, VirtAddr};
use crate::{print, virt_to_phys};
use crate::map_page_shared;
use core::cell::RefCell;
use crate::io::IOPort;
use core::arch::asm;

bitflags! {
	pub struct SEVStatusFlags: u64 {
		const SEV		= 1 << 0;
		const SEV_ES		= 1 << 1;
		const SEV_SNP		= 1 << 2;
		const VTOM		= 1 << 3;
		const REFLECT_VC	= 1 << 4;
		const REST_INJ		= 1 << 5;
		const ALT_INJ		= 1 << 6;
		const DBGSWP		= 1 << 7;
		const PREV_HOST_IBS	= 1 << 8;
		const BTB_ISOLATION	= 1 << 9;
		const SECURE_TSC	= 1 << 11;
		const VMSA_REG_PROT	= 1 << 16;
	}
}

static mut SEV_FLAGS : SEVStatusFlags = SEVStatusFlags::empty();

fn read_sev_status() -> SEVStatusFlags {
	SEVStatusFlags::from_bits_truncate(read_msr(SEV_STATUS))
}

fn print_sev_status(prefix : &str, status : SEVStatusFlags) {

	print!("{}", prefix);

	if status.contains(SEVStatusFlags::SEV) {
		print!(" SEV");
	}

	if status.contains(SEVStatusFlags::SEV_ES) {
		print!(" SEV-ES");
	}

	if status.contains(SEVStatusFlags::SEV_SNP) {
		print!(" SEV-SNP");
	}

	if status.contains(SEVStatusFlags::VTOM) {
		print!(" VTOM");
	}
	
	if status.contains(SEVStatusFlags::REFLECT_VC) {
		print!(" REFLECT_VC");
	}
	
	if status.contains(SEVStatusFlags::REST_INJ) {
		print!(" RESTRICTED_INJECTION");
	}
	
	if status.contains(SEVStatusFlags::ALT_INJ) {
		print!(" ALTERNATE_INJECTION");
	}
	
	if status.contains(SEVStatusFlags::DBGSWP) {
		print!(" DEBUG_SWAP");
	}

	if status.contains(SEVStatusFlags::PREV_HOST_IBS) {
		print!(" PREVENT_HOST_IBS");
	}

	if status.contains(SEVStatusFlags::BTB_ISOLATION) {
		print!(" SNP_BTB_ISOLATION");
	}

	if status.contains(SEVStatusFlags::SECURE_TSC) {
		print!(" SECURE_TSC");
	}

	if status.contains(SEVStatusFlags::VMSA_REG_PROT) {
		print!(" VMSA_REG_PROT");
	}
	
	print!("\n");
}

pub fn sev_status_init() {
	unsafe { SEV_FLAGS = read_sev_status() }
}

pub fn sev_init() {
	let status : SEVStatusFlags;
	let required = SEVStatusFlags::SEV | SEVStatusFlags::SEV_ES | SEVStatusFlags::SEV_SNP;
	let not_supported = SEVStatusFlags::VTOM | SEVStatusFlags::REFLECT_VC | SEVStatusFlags::REST_INJ |
			    SEVStatusFlags::ALT_INJ | SEVStatusFlags::DBGSWP | SEVStatusFlags::PREV_HOST_IBS |
			    SEVStatusFlags::BTB_ISOLATION | SEVStatusFlags::SECURE_TSC |
			    SEVStatusFlags::VMSA_REG_PROT;
	
	unsafe { status = SEV_FLAGS; }
	let required_check  = status & required;
	let supported_check = status & not_supported;

	print_sev_status("SEV Flags:", status);

	if required_check != required {
		print_sev_status("Required features not available:", required & !required_check);
		panic!("Required SEV features not available");
	}

	if !supported_check.is_empty() {
		print_sev_status("Unsupported features enabled:", supported_check);
		panic!("Unsupported SEV features enabled");
	}
}

pub fn sev_es_enabled() -> bool {
	unsafe { SEV_FLAGS.contains(SEVStatusFlags::SEV_ES) }
}

pub enum PValidateError {
	FailInput,
	FailSizeMismatch,
	FailUnknown,
	FailNotChanged,
}

pub fn pvalidate(vaddr : VirtAddr, huge_page: bool, valid : bool) -> Result<(),PValidateError> {
	let rax = vaddr;
	let rcx = { if huge_page { 1 } else { 0 } };
	let rdx = { if valid { 1 } else { 0 } };
	let ret : u64;
	let cf : u64;

	unsafe {
		asm!(".byte 0xf2, 0x0f, 0x01, 0xff",
		     "xorq %rcx, %rcx",
		     "jnc 1f",
		     "incq %rcx",
		     "1:",
		     in("rax")  rax,
		     in("rcx")  rcx,
		     in("rdx")  rdx,
		     lateout("rax") ret,
		     lateout("rcx") cf,
		     options(att_syntax));
	}

	if cf == 1 {
		return Err(PValidateError::FailNotChanged);
	}

	if ret == 0 {
		Ok(())
	} else if ret == 1 {
		Err(PValidateError::FailInput)
	} else if ret == 6 {
		Err(PValidateError::FailSizeMismatch)
	} else {
		Err(PValidateError::FailUnknown)
	}
}

fn raw_vmgexit() {
	unsafe {
		asm!("rep; vmmcall", options(att_syntax));
	}
}

#[non_exhaustive]
enum GHCBMsr {}

impl GHCBMsr {
	pub const SNP_REG_GHCB_GPA_REQ	: u64 = 0x12;
	pub const SNP_REG_GHCB_GPA_RESP	: u64 = 0x13;
	pub const SNP_STATE_CHANGE_REQ  : u64 = 0x14;
	pub const SNP_STATE_CHANGE_RESP : u64 = 0x15;
	pub const TERM_REQ		: u64 = 0x100;
}

pub fn register_ghcb_gpa_msr(addr: VirtAddr) -> Result<(),()> {
	let mut info : u64 = addr as u64;

	info |= GHCBMsr::SNP_REG_GHCB_GPA_REQ;
	write_msr(SEV_GHCB, info);
	raw_vmgexit();
	info = read_msr(SEV_GHCB);

	if (info & 0xfffu64) != GHCBMsr::SNP_REG_GHCB_GPA_RESP {
		return Err(());
	}

	if (info & !0xfffu64) == (addr as u64) {
		Ok(())
	} else {
		Err(())
	}
}

fn set_page_valid_status_msr(addr : PhysAddr, valid : bool) -> Result<(),()> {
	let mut info : u64 = (addr as u64) & 0x000f_ffff_ffff_f000;

	if valid {
		info |= 1u64 << 52;
	} else {
		info |= 2u64 << 52;
	}

	info |= GHCBMsr::SNP_STATE_CHANGE_REQ;
	write_msr(SEV_GHCB, info);
	raw_vmgexit();
	let response = read_msr(SEV_GHCB);

	if (response & !0xfffu64) != 0 {
		return Err(());
	}

	if (response & 0xfffu64) != GHCBMsr::SNP_STATE_CHANGE_RESP {
		return Err(());
	}

	Ok(())
}

pub fn validate_page_msr(addr: PhysAddr) -> Result<(),()> {
	set_page_valid_status_msr(addr, true)
}

pub fn invalidate_page_msr(addr: PhysAddr) -> Result<(),()> {
	set_page_valid_status_msr(addr, false)
}

pub fn request_termination_msr() {
	let info : u64 = GHCBMsr::TERM_REQ;

	write_msr(SEV_GHCB, info);
	raw_vmgexit();
	loop {};
}

// TODO: Fix this when Rust gets decent compile time struct offset support
const OFF_CPL			: u16 = 0xcb;
const OFF_XSS			: u16 = 0x140;
const OFF_DR7			: u16 = 0x160;
const OFF_RAX			: u16 = 0x1f8;
const OFF_RCX			: u16 = 0x308;
const OFF_RDX			: u16 = 0x310;
const OFF_RBX			: u16 = 0x318;
const OFF_SW_EXIT_CODE		: u16 = 0x390;
const OFF_SW_EXIT_INFO_1	: u16 = 0x398;
const OFF_SW_EXIT_INFO_2	: u16 = 0x3a0;
const OFF_SW_SCRATCH		: u16 = 0x3a8;
const OFF_XCR0			: u16 = 0x3e8;
const OFF_VALID_BITMAP		: u16 = 0x3f0;
const OFF_X87_STATE_GPA		: u16 = 0x400;
const _OFF_BUFFER		: u16 = 0x800;
const OFF_VERSION		: u16 = 0xffa;
const OFF_USAGE			: u16 = 0xffc;

#[repr(C, packed)]
pub struct PageStateChange {
	cur_entry : u16,
	end_entry : u16,
	reserved  : u32,
	entries   : [u64; 253],
}

pub enum PageStateChangeOp {
	PscPrivate,
	PscShared,
	PscPsmash,
	PscUnsmash,
}

const _PSC_GFN_MASK : u64 = ((1u64 << 52) - 1) & !0xfffu64;

const _PSC_OP_SHIFT : u8 = 52;
const _PSC_OP_PRIVATE : u64 = 1 << _PSC_OP_SHIFT;
const _PSC_OP_SHARED  : u64 = 2 << _PSC_OP_SHIFT;
const _PSC_OP_PSMASH  : u64 = 3 << _PSC_OP_SHIFT;
const _PSC_OP_UNSMASH : u64 = 4 << _PSC_OP_SHIFT;

const _PSC_FLAG_HUGE_SHIFT : u8 = 56;
const _PSC_FLAG_HUGE  : u64 = 1 << _PSC_FLAG_HUGE_SHIFT;

#[repr(C, packed)]
pub struct GHCB {
	reserved_1 : [u8; 0xcb],
	cpl : u8,
	reserved_2 : [u8; 0x74],
	xss : u64,
	reserved_3 : [u8; 0x18],
	dr7 : u64,
	reserved_4 : [u8; 0x90],
	rax : u64,
	reserved_5 : [u8; 0x100],
	reserved_6 : u64,
	rcx : u64,
	rdx : u64,
	rbx : u64,
	reserved_7 : [u8; 0x70],
	sw_exit_code : u64,
	sw_exit_info_1 : u64,
	sw_exit_info_2 : u64,
	sw_scratch: u64,
	reserved_8 : [u8; 0x38],
	xcr0 : u64,
	valid_bitmap : [u64; 2],
	x87_state_gpa : u64,
	reserved_9 : [u8; 0x3f8],
	buffer : [u8; 0x7f0],
	reserved_10 : [u8; 0xa],
	version : u16,
	usage : u32,
}

#[non_exhaustive]
enum GHCBExitCode {}

impl GHCBExitCode {
	pub const IOIO : u64 = 0x7b;
}

pub enum GHCBIOSize {
	Size8,
	Size16,
	Size32,
}

impl GHCB {
	
	pub fn init(&mut self) -> Result<(),()> {
		let vaddr = (self as *const GHCB) as VirtAddr;
		let paddr = virt_to_phys(vaddr);

		// Make page invalid
		if let Err(_e) = pvalidate(vaddr, false, false) {
			return Err(());
		}

		// Let the Hypervisor take the page back
		if let Err(_e) = invalidate_page_msr(paddr) {
			return Err(());
		}

		// Register GHCB GPA
		if let Err(_e) = register_ghcb_gpa_msr(paddr) {
			return Err(());
		}

		// Map page unencrypted
		if let Err(_e) = map_page_shared(vaddr) {
			return Err(());
		}

		flush_tlb_global();

		Ok(())
	}

	pub fn clear(&mut self) {
		// Clear valid bitmap
		self.valid_bitmap[0] = 0;
		self.valid_bitmap[1] = 0;

		// Mark valid_bitmap valid
		self.set_valid(OFF_VALID_BITMAP + 0);
		self.set_valid(OFF_VALID_BITMAP + 8);
	}

	fn set_valid(&mut self, offset : u16) {
		let bit   : usize = (offset as usize >> 3) & 0x3f;
		let index : usize = (offset as usize >> 9) & 0x1;
		let mask  : u64   = 1 << bit;

		self.valid_bitmap[index] |= mask;
	}

	fn is_valid(&self, offset : u16) -> bool {
		let bit   : usize = (offset as usize >> 3) & 0x3f;
		let index : usize = (offset as usize >> 9) & 0x1;
		let mask  : u64   = 1 << bit;

		(self.valid_bitmap[index] & mask) == mask
	}

	fn vmgexit(&mut self, exit_code : u64, exit_info_1 : u64, exit_info_2 : u64) -> Result<(),()> {
		// GHCB is version 2
		self.version = 2;
		self.set_valid(OFF_VERSION);

		// GHCB Follows standard format
		self.usage = 0;
		self.set_valid(OFF_USAGE);

		self.sw_exit_code = exit_code;
		self.set_valid(OFF_SW_EXIT_CODE);
		
		self.sw_exit_info_1 = exit_info_1;
		self.set_valid(OFF_SW_EXIT_INFO_1);

		self.sw_exit_info_2 = exit_info_2;
		self.set_valid(OFF_SW_EXIT_INFO_2);

		unsafe {
			let ghcb_address = (self as *const GHCB) as VirtAddr;
			let ghcb_pa : u64 = virt_to_phys(ghcb_address) as u64;
			write_msr(SEV_GHCB, ghcb_pa);
			asm!("rep; vmmcall", options(att_syntax));
		}

		if self.is_valid(OFF_SW_EXIT_INFO_1) && self.sw_exit_info_1 == 0 {
			Ok(())
		} else {
			Err(())
		}
	}

	pub fn set_cpl(&mut self, cpl : u8) {
		self.cpl = cpl;
		self.set_valid(OFF_CPL);
	}

	pub fn set_dr7(&mut self, dr7 : u64) {
		self.dr7 = dr7;
		self.set_valid(OFF_DR7);
	}

	pub fn set_xss(&mut self, xss : u64) {
		self.xss = xss;
		self.set_valid(OFF_XSS);
	}

	pub fn set_rax(&mut self, rax : u64) {
		self.rax = rax;
		self.set_valid(OFF_RAX);
	}

	pub fn set_rcx(&mut self, rcx : u64) {
		self.rcx = rcx;
		self.set_valid(OFF_RCX);
	}

	pub fn set_rdx(&mut self, rdx : u64) {
		self.rdx = rdx;
		self.set_valid(OFF_RDX);
	}

	pub fn set_rbx(&mut self, rbx : u64) {
		self.rbx = rbx;
		self.set_valid(OFF_RBX);
	}

	pub fn set_sw_scratch(&mut self, scratch : u64) {
		self.sw_scratch = scratch;
		self.set_valid(OFF_SW_SCRATCH);
	}

	pub fn set_sw_xcr0(&mut self, xcr0 : u64) {
		self.xcr0 = xcr0;
		self.set_valid(OFF_XCR0);
	}

	pub fn set_sw_x87_state_gpa(&mut self, x87_state_gpa : u64) {
		self.x87_state_gpa = x87_state_gpa;
		self.set_valid(OFF_X87_STATE_GPA);
	}

	pub fn ioio_in(&mut self, port : u16, size: GHCBIOSize) -> Result<u64,()> {
		self.clear();

		let mut info : u64 = 1; // IN instruction

		info |= (port as u64) << 16;

		match size {
			GHCBIOSize::Size8  => info |= 1 << 4,
			GHCBIOSize::Size16 => info |= 1 << 5,
			GHCBIOSize::Size32 => info |= 1 << 6,
		}

		match self.vmgexit(GHCBExitCode::IOIO, info, 0) {
			Ok(()) => {
				if self.is_valid(OFF_RAX) {
					Ok(self.rax)
				} else {
					Err(())
				}
			},
			Err(()) => Err(()),
		}
	}
	
	pub fn ioio_out(&mut self, port : u16, size: GHCBIOSize, value : u64) -> Result<(),()> {
		self.clear();

		let mut info : u64 = 0; // OUT instruction

		info |= (port as u64) << 16;

		match size {
			GHCBIOSize::Size8  => info |= 1 << 4,
			GHCBIOSize::Size16 => info |= 1 << 5,
			GHCBIOSize::Size32 => info |= 1 << 6,
		}

		self.set_rax(value);

		match self.vmgexit(GHCBExitCode::IOIO, info, 0) {
			Ok(()) => Ok(()),
			Err(()) => Err(()),
		}
	}
}


pub struct GHCBIOPort<'a> {
	pub ghcb: RefCell<&'a mut GHCB>,
}

impl<'a> GHCBIOPort<'a> {
	pub fn new(ghcb : RefCell<&'a mut GHCB>) -> Self {
		GHCBIOPort { ghcb : ghcb }
	}
}
unsafe impl<'a> Sync for GHCBIOPort<'a> { }

impl<'a> IOPort for GHCBIOPort<'a> {
	fn outb(&self, port: u16, value : u8) {
		let mut g = self.ghcb.borrow_mut();
		let ret = g.ioio_out(port, GHCBIOSize::Size8, value as u64);
		if let Err(()) = ret {
			request_termination_msr();
		}
	}

	fn inb(&self, port : u16) -> u8 {
		let mut g = self.ghcb.borrow_mut();
		let ret = g.ioio_in(port, GHCBIOSize::Size8);
		match ret {
			Ok(v)   => (v & 0xff) as u8,
			Err(_e) => { request_termination_msr(); 0},
		}
	}

	fn outw(&self, port: u16, value : u16) {
		let mut g = self.ghcb.borrow_mut();
		let ret = g.ioio_out(port, GHCBIOSize::Size16, value as u64);
		if let Err(()) = ret {
			request_termination_msr();
		}
	}

	fn inw(&self, port : u16) -> u16 {
		let mut g = self.ghcb.borrow_mut();
		let ret = g.ioio_in(port, GHCBIOSize::Size16);
		match ret {
			Ok(v)   => (v & 0xffff) as u16,
			Err(_e) => { request_termination_msr(); 0},
		}
	}
}

#[cfg(tests)]
mod tests {
	// The offset_of! macro seems to allocate a struct on the stack for each
	// invocation. For struct GHCB this means a full 4k allocation for every check,
	// which overflows the stack if all checks are in one function. Move the checks to
	// a separate function each to avoid this problem and lets hope for built-in Rust
	// support for struct offsets. Make sure the check functions are never inlined.

	#[inline(never)]
	fn check_offset_cpl() {
		assert_eq!(offset_of!(GHCB, cpl), OFF_CPL as usize);
	}

	#[inline(never)]
	fn check_offset_xss() {
		assert_eq!(offset_of!(GHCB, xss), OFF_XSS as usize);
	}

	#[inline(never)]
	fn check_offset_dr7() {
		assert_eq!(offset_of!(GHCB, dr7), OFF_DR7 as usize);
	}

	#[inline(never)]
	fn check_offset_rax() {
		assert_eq!(offset_of!(GHCB, rax), OFF_RAX as usize);
	}

	#[inline(never)]
	fn check_offset_rcx() {
		assert_eq!(offset_of!(GHCB, rcx), OFF_RCX as usize);
	}

	#[inline(never)]
	fn check_offset_rdx() {
		assert_eq!(offset_of!(GHCB, rdx), OFF_RDX as usize);
	}

	#[inline(never)]
	fn check_offset_rbx() {
		assert_eq!(offset_of!(GHCB, rbx), OFF_RBX as usize);
	}

	#[inline(never)]
	fn check_offset_sw_exit_code() {
		assert_eq!(offset_of!(GHCB, sw_exit_code), OFF_SW_EXIT_CODE as usize);
	}

	#[inline(never)]
	fn check_offset_sw_exit_info_1() {
		assert_eq!(offset_of!(GHCB, sw_exit_info_1), OFF_SW_EXIT_INFO_1 as usize);
	}

	#[inline(never)]
	fn check_offset_sw_exit_info_2() {
		assert_eq!(offset_of!(GHCB, sw_exit_info_2), OFF_SW_EXIT_INFO_2 as usize);
	}

	#[inline(never)]
	fn check_offset_sw_scratch() {
		assert_eq!(offset_of!(GHCB, sw_scratch), OFF_SW_SCRATCH as usize);
	}

	#[inline(never)]
	fn check_offset_xcr0() {
		assert_eq!(offset_of!(GHCB, xcr0), OFF_XCR0 as usize);
	}

	#[inline(never)]
	fn check_offset_valid_bitmap() {
		assert_eq!(offset_of!(GHCB, valid_bitmap), OFF_VALID_BITMAP as usize);
	}

	#[inline(never)]
	fn check_offset_x87_state_gpa() {
		assert_eq!(offset_of!(GHCB, x87_state_gpa), OFF_X87_STATE_GPA as usize);
	}

	#[inline(never)]
	fn check_offset_buffer() {
		assert_eq!(offset_of!(GHCB, buffer), _OFF_BUFFER as usize);
	}

	#[inline(never)]
	fn check_offset_version() {
		assert_eq!(offset_of!(GHCB, version), OFF_VERSION as usize);
	}

	#[inline(never)]
	fn check_offset_usage() {
		assert_eq!(offset_of!(GHCB, usage), OFF_USAGE as usize);
	}

	#[test]
	fn check_offsets()
	{
		check_offset_cpl();
		check_offset_xss();
		check_offset_dr7();
		check_offset_rax();
		check_offset_rcx();
		check_offset_rdx();
		check_offset_rbx();
		check_offset_sw_exit_code();
		check_offset_sw_exit_info_1();
		check_offset_sw_exit_info_2();
		check_offset_sw_scratch();
		check_offset_xcr0();
		check_offset_valid_bitmap();
		check_offset_x87_state_gpa();
		check_offset_buffer();
		check_offset_version();
		check_offset_usage();
		println!("GHCB Offsets OK");
	}
}

