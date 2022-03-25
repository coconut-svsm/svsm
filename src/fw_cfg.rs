use core::mem::size_of;
use super::io::{IOPort};
use crate::{println};
use super::string::{FixedString};

const FW_CFG_CTL	: u16 = 0x510;
const FW_CFG_DATA	: u16 = 0x511;

const FW_CFG_ID		: u16 = 0x01;
const FW_CFG_FILE_DIR	: u16 = 0x19;

#[non_exhaustive]

pub struct FwCfg<'a> {
	driver : &'a dyn IOPort,
}

struct FwCfgFile {
	size     : u32,
	selector : u16,
}


impl<'a> FwCfg<'a> {
	pub fn new(driver: &'a dyn IOPort) -> Self {
		FwCfg { driver : driver }
	}

	fn select(&self, cfg : u16) {
		let io = &self.driver;

		io.outw(FW_CFG_CTL, cfg);
	}

	fn read_le<T>(&self) -> T
	where
		T : core::ops::Shl<usize, Output = T> + core::ops::BitOr<T, Output = T> +
		    core::convert::From<u8> + core::convert::From<u8>,
	{
		let mut val = T::from(0u8);
		let io = &self.driver;

		for i in 0..size_of::<T>() {
			val = (T::from(io.inb(FW_CFG_DATA)) << (i * 8)) | val;
		}
		val
	}

	fn read_be<T>(&self) -> T
	where
		T : core::ops::Shl<usize, Output = T> + core::ops::BitOr<T, Output = T> +
		    core::convert::From<u8> + core::convert::From<u8>,
	{
		let mut val = T::from(0u8);
		let io = &self.driver;

		for _i in 0..size_of::<T>() {
			val = (val << 8) | T::from(io.inb(FW_CFG_DATA));
		}
		val
	}

	fn read_char(&self) -> char {
		let io = &self.driver;

		io.inb(FW_CFG_DATA) as char
	}

	fn file_selector(&self, str : &str) -> Result<FwCfgFile,()> {
		self.select(FW_CFG_ID);

		let version : u32 = self.read_le();

		println!("FW_CFG Version : {:#08x}", version);

		self.select(FW_CFG_FILE_DIR);
		let mut n : u32 = self.read_be();

		println!("FW_CFG Files: {}", n);

		while n != 0 {
			let size    : u32 = self.read_be();
			let select  : u16 = self.read_be();
			let _unused : u16 = self.read_be();
			let mut fs = FixedString::<56>::new();
			for _i in 0..56 {
				let c = self.read_char();
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

	pub fn read_e820(&self) -> Result<(),()> {
		let result = self.file_selector("etc/e820");

		if let Err(e) = result {
			return Err(e);
		}

		let file = result.unwrap();

		self.select(file.selector);

		let entries = file.size / 20;

		println!("E280 File Size: {}", file.size);
		for _i in 0..entries {
			let start : u64 = self.read_le();
			let size  : u64 = self.read_le();
			let t     : u32 = self.read_le();

			println!("E820: start: {:#08x} size: {:#08x} type: {}", start, size, t);
		}
		Ok(())
	}
}
