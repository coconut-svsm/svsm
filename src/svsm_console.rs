use crate::cpu::percpu::this_cpu_ghcb;
use crate::io::IOPort;
use crate::sev::{GHCBIOSize, request_termination_msr};

pub struct SVSMIOPort {
}

impl SVSMIOPort {
	pub const fn new() -> Self {
		SVSMIOPort { }
	}
}

impl IOPort for SVSMIOPort {
	fn outb(&self, port: u16, value : u8) {
		let g = this_cpu_ghcb();
		let ret = g.ioio_out(port, GHCBIOSize::Size8, value as u64);
		if let Err(()) = ret {
			request_termination_msr();
		}
	}

	fn inb(&self, port : u16) -> u8 {
		let g = this_cpu_ghcb();
		let ret = g.ioio_in(port, GHCBIOSize::Size8);
		match ret {
			Ok(v)   => (v & 0xff) as u8,
			Err(_e) => { request_termination_msr(); 0},
		}
	}

	fn outw(&self, port: u16, value : u16) {
		let g = this_cpu_ghcb();
		let ret = g.ioio_out(port, GHCBIOSize::Size16, value as u64);
		if let Err(()) = ret {
			request_termination_msr();
		}
	}

	fn inw(&self, port : u16) -> u16 {
		let g = this_cpu_ghcb();
		let ret = g.ioio_in(port, GHCBIOSize::Size16);
		match ret {
			Ok(v)   => (v & 0xffff) as u16,
			Err(_e) => { request_termination_msr(); 0},
		}
	}
}


