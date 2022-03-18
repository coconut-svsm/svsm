use core::mem::size_of;
use super::io::{inb, outw};
use crate::{println};
use super::string::{FixedString};

const FW_CFG_CTL  : u16 = 0x510;
const FW_CFG_DATA : u16 = 0x511;

#[non_exhaustive]
enum FwCfg {}

impl FwCfg {
	pub const ID		: u16 = 0x01;
	pub const FILE_DIR	: u16 = 0x19;
}

fn fw_cfg_select(cfg : u16) {
	outw(FW_CFG_CTL, cfg);
}

pub fn fw_cfg_read_le<T>() -> T
where
	T : core::ops::Shl<usize, Output = T> + core::ops::BitOr<T, Output = T> +
	    core::convert::From<u8> + core::convert::From<u8>,
{
	let mut val = T::from(0u8);

	for i in 0..size_of::<T>() {
		val = (T::from(inb(FW_CFG_DATA)) << (i * 8)) | val;
	}
	val
}

pub fn fw_cfg_read_be<T>() -> T
where
	T : core::ops::Shl<usize, Output = T> + core::ops::BitOr<T, Output = T> +
	    core::convert::From<u8> + core::convert::From<u8>,
{
	let mut val = T::from(0u8);

	for _i in 0..size_of::<T>() {
		val = (val << 8) | T::from(inb(FW_CFG_DATA));
	}
	val
}

struct FwCfgFile {
	size     : u32,
	selector : u16,
}

fn fw_cfg_file_selector(str : &str) -> Result<FwCfgFile,()> {
	fw_cfg_select(FwCfg::ID);

	let version : u32 = fw_cfg_read_le();

	println!("FW_CFG Version : {:#08x}", version);

	fw_cfg_select(FwCfg::FILE_DIR);
	let mut n : u32 = fw_cfg_read_be();

	println!("FW_CFG Files: {}", n);

	while n != 0 {
		let size    : u32 = fw_cfg_read_be();
		let select  : u16 = fw_cfg_read_be();
		let _unused : u16 = fw_cfg_read_be();
		let mut fs = FixedString::<56>::new();
		for _i in 0..56 {
			let c = inb(FW_CFG_DATA) as char;
			fs.push(c);
		}
		println!("FW_CFG File: (size: {:#08x} select: {:#04x}) name: \"{}\"", size, select, fs);
		if fs.equal_str(str) {
			println!("Found {}", str);
			return Ok( FwCfgFile { size : size, selector : select } );
		}
		n -= 1;
	}
	Err(())
}

pub fn fw_cfg_read_e820() -> Result<(),()> {
	let result = fw_cfg_file_selector("etc/e820");

	if let Err(e) = result {
		return Err(e);
	}

	let file = result.unwrap();

	fw_cfg_select(file.selector);

	let entries = file.size / 20;

	println!("E280 File Size: {}", file.size);
	for _i in 0..entries {
		let start : u64 = fw_cfg_read_le();
		let size  : u64 = fw_cfg_read_le();
		let t     : u32 = fw_cfg_read_le();

		println!("E820: start: {:#08x} size: {:#08x} type: {}", start, size, t);
	}
	Ok(())
}
