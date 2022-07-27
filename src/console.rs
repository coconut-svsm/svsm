use crate::locking::SpinLock;
use core::fmt;
use crate::serial::DEFAULT_SERIAL_PORT;

pub trait ConsoleWriter {
	fn put_byte(&self, _ch : u8) { }
}

pub struct Console {
	writer : *mut dyn ConsoleWriter,
}

impl Console {
	pub fn set(&mut self, w : *mut dyn ConsoleWriter) {
		self.writer = w;
	}
}

impl fmt::Write for Console {
	fn write_str(&mut self, s: &str) -> fmt::Result {

		if self.writer.is_null() {
			return Ok(());
		}

		for ch in s.bytes() {
			unsafe { (*self.writer).put_byte(ch); }
		}

		Ok(())
	}
}

pub static mut WRITER: SpinLock<Console> = SpinLock::new(unsafe { Console { writer : &mut DEFAULT_SERIAL_PORT } } );

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
	use core::fmt::Write;
	unsafe { WRITER.lock().write_fmt(args).unwrap(); }
}

