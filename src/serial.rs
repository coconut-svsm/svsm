use core::fmt;
use super::locking::SpinLock;
use super::io::{inb, outb};

pub const SERIAL_PORT : u16 =  0x3f8;
const BAUD : u32 = 9600;
const DLAB : u8 = 0x80;

const  TXR : u16 = 0;	// Transmit register
const _RXR : u16 = 0;	// Receive register
const  IER : u16 = 1;	// Interrupt enable
const _IIR : u16 = 2;	// Interrupt ID
const  FCR : u16 = 2;	// FIFO Control
const  LCR : u16 = 3;	// Line Control
const  MCR : u16 = 4;	// Modem Control
const  LSR : u16 = 5;	// Line Status
const _MSR : u16 = 6;	// Modem Status
const  DLL : u16 = 0;	// Divisor Latch Low
const  DLH : u16 = 1;	// Divisor Latch High

const XMTRDY : u8 = 0x20;

fn serial_init(port : u16) {
	let divisor : u32 =  115200 / BAUD;

	outb(port + LCR, 0x3);	// 8n1
	outb(port + IER, 0);  // No Interrupt
	outb(port + FCR, 0);  // No FIFO
	outb(port + MCR, 0x3);  // DTR + RTS

	let c = inb(port + LCR);
	outb(port + LCR, c | DLAB);
	outb(port + DLL, (divisor & 0xff) as u8);
	outb(port + DLH, ((divisor >> 8) & 0xff) as u8);
	outb(port + LCR, c & !DLAB);
}

fn serial_put_char(port : u16, ch : u8) {
	loop {
		let xmt = inb(port + LSR);
		if (xmt & XMTRDY) == XMTRDY {
			break;
		}
	}
	outb(port + TXR, ch)
}

pub struct SerialWriter {
	port : u16,

}

impl SerialWriter {
	pub fn new(p : u16) -> Self {
		serial_init(p);
		SerialWriter {
			port: p,
		}
	}
}

impl fmt::Write for SerialWriter {
	fn write_str(&mut self, s: &str) -> fmt::Result {
		for ch in s.bytes() {
			serial_put_char(self.port, ch);
		}
		Ok(())
	}
}

pub static mut WRITER: SpinLock<SerialWriter> = SpinLock::new(SerialWriter { port : SERIAL_PORT });

#[macro_export]
macro_rules! print {
	($($arg:tt)*) => ($crate::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
	() => ($crate::print!("\n"));
	($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
	use core::fmt::Write;
	unsafe { WRITER.lock().write_fmt(args).unwrap(); }
}
