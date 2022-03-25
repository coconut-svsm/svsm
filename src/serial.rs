use crate::console::ConsoleWriter;
use super::io::{IOPort, DEFAULT_IO_DRIVER};

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

pub struct SerialPort<'a>
{
	pub driver : &'a dyn IOPort,
	pub port   : u16,
}

impl<'a> SerialPort<'a> {
	pub fn new(driver: &'a dyn IOPort, p : u16) -> Self {
		SerialPort {
			driver: driver,
			port: p,
		}
	}

	pub fn init(&self) {
		let divisor : u32 =  115200 / BAUD;
		let driver = &self.driver;
		let port = self.port;

		driver.outb(port + LCR, 0x3);	// 8n1
		driver.outb(port + IER, 0);  // No Interrupt
		driver.outb(port + FCR, 0);  // No FIFO
		driver.outb(port + MCR, 0x3);  // DTR + RTS

		let c = driver.inb(port + LCR);
		driver.outb(port + LCR, c | DLAB);
		driver.outb(port + DLL, (divisor & 0xff) as u8);
		driver.outb(port + DLH, ((divisor >> 8) & 0xff) as u8);
		driver.outb(port + LCR, c & !DLAB);
	}
}

impl<'a> ConsoleWriter for SerialPort<'a> {
	fn put_byte(&self, ch : u8) {
		let driver = &self.driver;
		let port = self.port;

		loop {
			let xmt = driver.inb(port + LSR);
			if (xmt & XMTRDY) == XMTRDY {
				break;
			}
		}

		driver.outb(port + TXR, ch)
	}
}

pub static mut DEFAULT_SERIAL_PORT : SerialPort = SerialPort { driver : &DEFAULT_IO_DRIVER, port : SERIAL_PORT };
